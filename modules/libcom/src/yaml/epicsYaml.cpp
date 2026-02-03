// SPDX-License-Identifier: EPICS

#include "epicsYaml.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Span {
    std::string filename;
    unsigned line = 1;
    unsigned column = 1;
};

struct Node {
    epicsYamlKind kind = epicsYaml_Null;
    Span span;

    bool b = false;
    epicsInt64 i = 0;
    double d = 0.0;
    std::string s;

    std::vector<std::pair<std::string, std::unique_ptr<Node>>> map; // ordered
    std::vector<std::unique_ptr<Node>> seq;
};

struct Document {
    std::unique_ptr<Node> root;
    epicsYamlLimits limits{};
    size_t nodeCount = 0;
};

static epicsYamlLimits withDefaults(epicsYamlLimits lim)
{
    if (!lim.maxFileBytes) lim.maxFileBytes = 1024u * 1024u;
    if (!lim.maxDepth) lim.maxDepth = 64u;
    if (!lim.maxNodes) lim.maxNodes = 200000u;
    if (!lim.maxLineBytes) lim.maxLineBytes = 16384u;
    return lim;
}

static void diag(epicsYamlDiagFn fn, void* user,
                 const Span& sp, epicsYamlSeverity sev,
                 const std::string& msg)
{
    if (!fn) return;
    epicsYamlDiag d{sp.filename.c_str(), sp.line, sp.column, sev, msg.c_str()};
    fn(user, &d);
}

static bool endsWithNoCase(const std::string& s, const char* suffix)
{
    const size_t n = s.size();
    const size_t m = strlen(suffix);
    if (m > n) return false;
    for (size_t i = 0; i < m; ++i) {
        char a = s[n - m + i];
        char b = suffix[i];
        if (tolower((unsigned char)a) != tolower((unsigned char)b)) return false;
    }
    return true;
}

static std::string stripComment(const std::string& line)
{
    // restricted subset: comments start with '#' when not in quotes
    bool inS = false, inD = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '\\' && inD) {
            // skip escaped char in double quotes
            if (i + 1 < line.size()) ++i;
            continue;
        }
        if (!inD && c == '\'' ) inS = !inS;
        else if (!inS && c == '"') inD = !inD;
        else if (!inS && !inD && c == '#') {
            return line.substr(0, i);
        }
    }
    return line;
}

static bool isSpaceOnly(const std::string& s)
{
    for (char c : s) {
        if (c != ' ' && c != '\r' && c != '\n' && c != '\t') return false;
    }
    return true;
}

static size_t leadingSpaces(const std::string& s, Span& sp, epicsYamlDiagFn diagFn, void* diagUser)
{
    size_t n = 0;
    for (; n < s.size(); ++n) {
        char c = s[n];
        if (c == ' ') continue;
        if (c == '\t') {
            sp.column = (unsigned)(n + 1);
            diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "tabs are not allowed for indentation");
        }
        break;
    }
    return n;
}

static std::string rtrim(std::string s)
{
    while (!s.empty()) {
        char c = s.back();
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') s.pop_back();
        else break;
    }
    return s;
}

static bool parseBool(const std::string& v, bool& out)
{
    if (v == "true") { out = true; return true; }
    if (v == "false") { out = false; return true; }
    return false;
}

static bool parseNull(const std::string& v)
{
    return v == "null" || v == "~";
}

static bool parseInt(const std::string& v, epicsInt64& out)
{
    if (v.empty()) return false;
    size_t i = 0;
    bool neg = false;
    if (v[0] == '-') { neg = true; i = 1; }
    if (i >= v.size()) return false;
    epicsInt64 acc = 0;
    for (; i < v.size(); ++i) {
        char c = v[i];
        if (c < '0' || c > '9') return false;
        int dig = c - '0';
        if (acc > (std::numeric_limits<epicsInt64>::max() - dig) / 10) return false;
        acc = acc * 10 + dig;
    }
    out = neg ? -acc : acc;
    return true;
}

static bool parseDouble(const std::string& v, double& out)
{
    // restricted: decimal float with optional leading '-', digits, optional fraction
    // (no exponent support initially)
    bool sawDot = false;
    size_t i = 0;
    if (v.empty()) return false;
    if (v[0] == '-') i = 1;
    if (i >= v.size()) return false;
    bool sawDigit = false;
    for (; i < v.size(); ++i) {
        char c = v[i];
        if (c == '.') {
            if (sawDot) return false;
            sawDot = true;
        } else if (c >= '0' && c <= '9') {
            sawDigit = true;
        } else {
            return false;
        }
    }
    if (!sawDot || !sawDigit) return false;
    char* endp = nullptr;
    errno = 0;
    out = strtod(v.c_str(), &endp);
    if (errno || !endp || *endp) return false;
    return true;
}

static bool startsWith(const std::string& s, const char* p)
{
    size_t i = 0;
    for (; p[i]; ++i) {
        if (i >= s.size() || s[i] != p[i]) return false;
    }
    return true;
}

static std::string unquote(const std::string& v, Span& sp, epicsYamlDiagFn diagFn, void* diagUser)
{
    if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'') {
        // single quotes: no escapes, doubled '' not supported in subset
        return v.substr(1, v.size() - 2);
    }
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
        std::string out;
        out.reserve(v.size());
        for (size_t i = 1; i + 1 < v.size(); ++i) {
            char c = v[i];
            if (c == '\\') {
                if (i + 1 >= v.size() - 1) {
                    sp.column += (unsigned)i;
                    diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "unterminated escape in double-quoted string");
                    break;
                }
                char e = v[++i];
                switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                default:
                    // restricted: only basic escapes
                    out.push_back(e);
                    break;
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }
    return v;
}

static std::unique_ptr<Node> makeNode(Document& doc, epicsYamlKind k, const Span& sp)
{
    if (doc.nodeCount >= doc.limits.maxNodes) {
        throw std::runtime_error("YAML node limit exceeded");
    }
    doc.nodeCount++;
    std::unique_ptr<Node> n(new Node);
    n->kind = k;
    n->span = sp;
    return n;
}

struct Frame {
    Node* node = nullptr;
    size_t indent = 0;
    // if this frame is for a pending container value (kind unknown until first child)
    bool pending = false;
};

static void ensureContainerKind(Node& n, epicsYamlKind want)
{
    if (n.kind == epicsYaml_Null) {
        n.kind = want;
        return;
    }
    if (n.kind != want) {
        throw std::runtime_error("YAML structure mismatch");
    }
}

static std::unique_ptr<Document> parse(const std::string& filename,
                                       const std::vector<std::string>& lines,
                                       epicsYamlLimits lim,
                                       epicsYamlDiagFn diagFn, void* diagUser)
{
    auto doc = std::unique_ptr<Document>(new Document);
    doc->limits = withDefaults(lim);

    Span sp{filename, 1u, 1u};
    doc->root = makeNode(*doc, epicsYaml_Null, sp);

    std::vector<Frame> stack;
    stack.push_back(Frame{doc->root.get(), 0u, true});

    for (size_t li = 0; li < lines.size(); ++li) {
        sp.line = (unsigned)(li + 1);
        sp.column = 1;

        std::string raw = lines[li];
        if (raw.size() > doc->limits.maxLineBytes) {
            diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "line too long");
            throw std::runtime_error("line too long");
        }

        // drop document start marker if present
        if (li == 0) {
            std::string t = rtrim(stripComment(raw));
            if (startsWith(t, "---")) {
                continue;
            }
        }

        raw = rtrim(stripComment(raw));
        if (raw.empty() || isSpaceOnly(raw)) continue;

        size_t ind = leadingSpaces(raw, sp, diagFn, diagUser);
        if (ind >= raw.size()) continue;

        // adjust stack for indentation
        while (stack.size() > 1 && ind < stack.back().indent) {
            stack.pop_back();
        }
        if (ind > stack.back().indent) {
            // must be a child of the previous node, which must be pending
            if (!stack.back().pending) {
                diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "unexpected indentation");
                throw std::runtime_error("unexpected indentation");
            }
            if (stack.size() >= doc->limits.maxDepth) {
                diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "maximum nesting depth exceeded");
                throw std::runtime_error("depth exceeded");
            }
            // keep current frame; this line will decide whether seq/map
        } else if (ind != stack.back().indent) {
            // ind < indent already handled by pops; any other mismatch is error
            // (restricted subset demands consistent indentation levels)
            diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "inconsistent indentation");
            throw std::runtime_error("inconsistent indentation");
        }

        Frame& parentF = stack.back();
        Node* parent = parentF.node;

        std::string content = raw.substr(ind);
        sp.column = (unsigned)(ind + 1);

        auto parseScalar = [&](const std::string& val, const Span& vsp) -> std::unique_ptr<Node> {
            std::string v = val;
            // trim leading spaces
            while (!v.empty() && v.front() == ' ') v.erase(v.begin());
            // trim trailing spaces
            v = rtrim(v);

            if (v.empty()) {
                return makeNode(*doc, epicsYaml_Null, vsp);
            }

            // disallow flow collections and block scalars in restricted subset
            if (v[0] == '{' || v[0] == '[' || v[0] == '|' || v[0] == '>') {
                diag(diagFn, diagUser, vsp, epicsYaml_Severity_Error, "unsupported YAML feature (flow collection or block scalar)");
                throw std::runtime_error("unsupported YAML feature");
            }

            if (v.size() >= 2 && ((v.front() == '\'' && v.back() == '\'') || (v.front() == '"' && v.back() == '"'))) {
                auto n = makeNode(*doc, epicsYaml_String, vsp);
                Span qsp = vsp;
                n->s = unquote(v, qsp, diagFn, diagUser);
                return n;
            }

            bool b;
            if (parseBool(v, b)) {
                auto n = makeNode(*doc, epicsYaml_Bool, vsp);
                n->b = b;
                return n;
            }
            if (parseNull(v)) {
                return makeNode(*doc, epicsYaml_Null, vsp);
            }
            epicsInt64 i;
            if (parseInt(v, i)) {
                auto n = makeNode(*doc, epicsYaml_Int, vsp);
                n->i = i;
                return n;
            }
            double dd;
            if (parseDouble(v, dd)) {
                auto n = makeNode(*doc, epicsYaml_Double, vsp);
                n->d = dd;
                return n;
            }

            auto n = makeNode(*doc, epicsYaml_String, vsp);
            n->s = v;
            return n;
        };

        auto addChildFrameIfPending = [&](Node* n, size_t childIndent) {
            stack.push_back(Frame{n, childIndent, true});
        };

        auto isSeqItem = [&]() -> bool {
            return content.size() >= 1 && content[0] == '-' && (content.size() == 1 || content[1] == ' ');
        };

        if (isSeqItem()) {
            // sequence element
            if (parentF.pending) {
                ensureContainerKind(*parent, epicsYaml_Seq);
                parentF.pending = false;
            } else {
                ensureContainerKind(*parent, epicsYaml_Seq);
            }

            std::string rest = content.size() > 1 ? content.substr(1) : std::string();
            // rest begins with space or empty
            while (!rest.empty() && rest.front() == ' ') rest.erase(rest.begin());

            Span vsp = sp;
            vsp.column = (unsigned)(ind + 1 + 2); // approx after "- "

            if (rest.empty()) {
                auto child = makeNode(*doc, epicsYaml_Null, vsp);
                Node* childPtr = child.get();
                parent->seq.emplace_back(std::move(child));
                addChildFrameIfPending(childPtr, ind + 2);
            } else {
                // Support common YAML pattern: "- key: value" (sequence of mappings)
                bool rinS = false, rinD = false;
                size_t rcolon = std::string::npos;
                for (size_t i = 0; i < rest.size(); ++i) {
                    char c = rest[i];
                    if (c == '\\' && rinD) {
                        if (i + 1 < rest.size()) ++i;
                        continue;
                    }
                    if (!rinD && c == '\'') rinS = !rinS;
                    else if (!rinS && c == '"') rinD = !rinD;
                    else if (!rinS && !rinD && c == ':') {
                        rcolon = i;
                        break;
                    }
                }

                if (rcolon != std::string::npos) {
                    // child is a map with first entry coming from this line
                    auto childMap = makeNode(*doc, epicsYaml_Map, vsp);

                    std::string kraw = rtrim(rest.substr(0, rcolon));
                    std::string vraw = rest.substr(rcolon + 1);
                    while (!vraw.empty() && vraw.front() == ' ') vraw.erase(vraw.begin());
                    if (kraw.empty()) {
                        diag(diagFn, diagUser, vsp, epicsYaml_Severity_Error, "empty mapping key is not supported");
                        throw std::runtime_error("empty key");
                    }
                    Span ksp = vsp;
                    Span vsp2 = vsp;
                    vsp2.column = (unsigned)(vsp.column + rcolon + 2);

                    std::string key = unquote(kraw, ksp, diagFn, diagUser);

                    if (vraw.empty()) {
                        auto val = makeNode(*doc, epicsYaml_Null, vsp2);
                        Node* valPtr = val.get();
                        childMap->map.emplace_back(key, std::move(val));
                        Node* childPtr = childMap.get();
                        parent->seq.emplace_back(std::move(childMap));

                        // allow additional keys at indent ind+2
                        stack.push_back(Frame{childPtr, ind + 2, false});
                        // and allow nested content for this key at indent ind+4
                        stack.push_back(Frame{valPtr, ind + 4, true});
                    } else {
                        auto val = parseScalar(vraw, vsp2);
                        childMap->map.emplace_back(key, std::move(val));
                        Node* childPtr = childMap.get();
                        parent->seq.emplace_back(std::move(childMap));

                        // allow additional keys at indent ind+2
                        stack.push_back(Frame{childPtr, ind + 2, false});
                    }
                } else {
                    auto child = parseScalar(rest, vsp);
                    parent->seq.emplace_back(std::move(child));
                }
            }
            continue;
        }

        // mapping entry: key: value
        // restricted subset: key cannot be empty and must contain ':'
        bool inS = false, inD = false;
        size_t colon = std::string::npos;
        for (size_t i = 0; i < content.size(); ++i) {
            char c = content[i];
            if (c == '\\' && inD) {
                if (i + 1 < content.size()) ++i;
                continue;
            }
            if (!inD && c == '\'') inS = !inS;
            else if (!inS && c == '"') inD = !inD;
            else if (!inS && !inD && c == ':') {
                colon = i;
                break;
            }
        }
        if (colon == std::string::npos) {
            diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "expected mapping entry (missing ':')");
            throw std::runtime_error("missing ':'");
        }

        if (parentF.pending) {
            ensureContainerKind(*parent, epicsYaml_Map);
            parentF.pending = false;
        } else {
            ensureContainerKind(*parent, epicsYaml_Map);
        }

        std::string kraw = rtrim(content.substr(0, colon));
        std::string vraw = content.substr(colon + 1);
        // trim leading spaces from vraw
        while (!vraw.empty() && vraw.front() == ' ') vraw.erase(vraw.begin());

        Span ksp = sp;
        Span vsp = sp;
        vsp.column = (unsigned)(ind + 1 + colon + 2);

        if (kraw.empty()) {
            diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "empty mapping key is not supported");
            throw std::runtime_error("empty key");
        }
        if (kraw.front() == '{' || kraw.front() == '[') {
            diag(diagFn, diagUser, ksp, epicsYaml_Severity_Error, "unsupported YAML feature (complex/flow key)");
            throw std::runtime_error("unsupported key");
        }

        std::string key = unquote(kraw, ksp, diagFn, diagUser);

        // disallow duplicate keys within same map
        for (const auto& kv : parent->map) {
            if (kv.first == key) {
                diag(diagFn, diagUser, ksp, epicsYaml_Severity_Error, "duplicate mapping key: " + key);
                throw std::runtime_error("duplicate key");
            }
        }

        if (vraw.empty()) {
            auto child = makeNode(*doc, epicsYaml_Null, vsp);
            Node* childPtr = child.get();
            parent->map.emplace_back(key, std::move(child));
            addChildFrameIfPending(childPtr, ind + 2);
        } else {
            auto child = parseScalar(vraw, vsp);
            parent->map.emplace_back(key, std::move(child));
        }
    }

    if (doc->root->kind == epicsYaml_Null) {
        // empty document is treated as empty map
        doc->root->kind = epicsYaml_Map;
    }
    return doc;
}

static std::vector<std::string> readAllLines(const std::string& filename, const epicsYamlLimits& lim,
                                             Span& sp, epicsYamlDiagFn diagFn, void* diagUser)
{
    FILE* fp = fopen(filename.c_str(), "r");
    if (!fp) {
        diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "failed to open file");
        throw std::runtime_error("open failed");
    }
    std::vector<std::string> lines;
    std::string cur;
    cur.reserve(256);
    size_t total = 0;
    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        total++;
        if (total > lim.maxFileBytes) {
            fclose(fp);
            diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "file too large");
            throw std::runtime_error("file too large");
        }
        if (ch == '\n') {
            lines.push_back(cur);
            cur.clear();
        } else if (ch == '\r') {
            // ignore; allow CRLF
        } else {
            cur.push_back((char)ch);
        }
    }
    if (!cur.empty()) lines.push_back(cur);
    fclose(fp);
    return lines;
}

static std::vector<std::string> readAllLinesFP(FILE* fp, const epicsYamlLimits& lim,
                                               Span& sp, epicsYamlDiagFn diagFn, void* diagUser)
{
    if (!fp) {
        diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "null FILE*");
        throw std::runtime_error("null FILE*");
    }
    std::vector<std::string> lines;
    std::string cur;
    cur.reserve(256);
    size_t total = 0;
    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        total++;
        if (total > lim.maxFileBytes) {
            diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, "file too large");
            throw std::runtime_error("file too large");
        }
        if (ch == '\n') {
            lines.push_back(cur);
            cur.clear();
        } else if (ch == '\r') {
            // ignore; allow CRLF
        } else {
            cur.push_back((char)ch);
        }
    }
    if (!cur.empty()) lines.push_back(cur);
    return lines;
}

} // namespace

extern "C" {

struct epicsYamlDocument {
    std::unique_ptr<Document> impl;
};
/* epicsYamlNode is an opaque handle declared in the public header.
 * We treat it as an alias for the internal Node type.
 */

static inline const Node* unwrap(const epicsYamlNode* n) {
    return reinterpret_cast<const Node*>(n);
}
static inline const epicsYamlNode* wrap(const Node* n) {
    return reinterpret_cast<const epicsYamlNode*>(n);
}

int epicsStdCall epicsYamlIsYamlFilename(const char* filename)
{
    if (!filename) return 0;
    std::string f(filename);
    return endsWithNoCase(f, ".yaml") || endsWithNoCase(f, ".yml");
}

epicsYamlDocument* epicsStdCall epicsYamlParseFile(
    const char* filename,
    const epicsYamlLimits* limits,
    epicsYamlDiagFn diagFn,
    void* diagUser)
{
    if (!filename) return nullptr;
    epicsYamlLimits lim = limits ? *limits : epicsYamlLimits{};
    lim = withDefaults(lim);
    Span sp{filename, 1u, 1u};

    try {
        auto lines = readAllLines(filename, lim, sp, diagFn, diagUser);
        auto docImpl = parse(filename, lines, lim, diagFn, diagUser);
        auto out = new epicsYamlDocument;
        out->impl = std::move(docImpl);
        return out;
    } catch (const std::exception& e) {
        diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, e.what());
        return nullptr;
    }
}

epicsYamlDocument* epicsStdCall epicsYamlParseFP(
    FILE* fp,
    const char* displayName,
    const epicsYamlLimits* limits,
    epicsYamlDiagFn diagFn,
    void* diagUser)
{
    epicsYamlLimits lim = limits ? *limits : epicsYamlLimits{};
    lim = withDefaults(lim);

    const char* name = displayName ? displayName : "<stream>";
    Span sp{name, 1u, 1u};

    try {
        auto lines = readAllLinesFP(fp, lim, sp, diagFn, diagUser);
        auto docImpl = parse(name, lines, lim, diagFn, diagUser);
        auto out = new epicsYamlDocument;
        out->impl = std::move(docImpl);
        return out;
    } catch (const std::exception& e) {
        diag(diagFn, diagUser, sp, epicsYaml_Severity_Error, e.what());
        return nullptr;
    }
}

void epicsStdCall epicsYamlDocFree(epicsYamlDocument* doc)
{
    delete doc;
}

const epicsYamlNode* epicsStdCall epicsYamlDocRoot(const epicsYamlDocument* doc)
{
    if (!doc || !doc->impl || !doc->impl->root) return nullptr;
    return wrap(doc->impl->root.get());
}

epicsYamlKind epicsStdCall epicsYamlNodeKind(const epicsYamlNode* node)
{
    const Node* n = unwrap(node);
    return n ? n->kind : epicsYaml_Null;
}

int epicsStdCall epicsYamlNodeGetBool(const epicsYamlNode* node, int* out)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Bool || !out) return -1;
    *out = n->b ? 1 : 0;
    return 0;
}

int epicsStdCall epicsYamlNodeGetInt64(const epicsYamlNode* node, epicsInt64* out)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Int || !out) return -1;
    *out = n->i;
    return 0;
}

int epicsStdCall epicsYamlNodeGetDouble(const epicsYamlNode* node, double* out)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Double || !out) return -1;
    *out = n->d;
    return 0;
}

int epicsStdCall epicsYamlNodeGetString(const epicsYamlNode* node, const char** out)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_String || !out) return -1;
    *out = n->s.c_str();
    return 0;
}

size_t epicsStdCall epicsYamlNodeMapSize(const epicsYamlNode* node)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Map) return 0u;
    return n->map.size();
}

const char* epicsStdCall epicsYamlNodeMapKeyAt(const epicsYamlNode* node, size_t idx)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Map || idx >= n->map.size()) return nullptr;
    return n->map[idx].first.c_str();
}

const epicsYamlNode* epicsStdCall epicsYamlNodeMapValueAt(const epicsYamlNode* node, size_t idx)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Map || idx >= n->map.size()) return nullptr;
    return wrap(n->map[idx].second.get());
}

const epicsYamlNode* epicsStdCall epicsYamlNodeMapFind(const epicsYamlNode* node, const char* key)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Map || !key) return nullptr;
    for (const auto& kv : n->map) {
        if (kv.first == key) return wrap(kv.second.get());
    }
    return nullptr;
}

size_t epicsStdCall epicsYamlNodeSeqSize(const epicsYamlNode* node)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Seq) return 0u;
    return n->seq.size();
}

const epicsYamlNode* epicsStdCall epicsYamlNodeSeqAt(const epicsYamlNode* node, size_t idx)
{
    const Node* n = unwrap(node);
    if (!n || n->kind != epicsYaml_Seq || idx >= n->seq.size()) return nullptr;
    return wrap(n->seq[idx].get());
}

const char* epicsStdCall epicsYamlNodeFilename(const epicsYamlNode* node)
{
    const Node* n = unwrap(node);
    return n ? n->span.filename.c_str() : nullptr;
}

unsigned epicsStdCall epicsYamlNodeLine(const epicsYamlNode* node)
{
    const Node* n = unwrap(node);
    return n ? n->span.line : 0u;
}

unsigned epicsStdCall epicsYamlNodeColumn(const epicsYamlNode* node)
{
    const Node* n = unwrap(node);
    return n ? n->span.column : 0u;
}

} // extern "C"
