// SPDX-License-Identifier: EPICS

#include "asLib.h"
#include "epicsYaml.h"

#include "epicsTempFile.h"
#include "errlog.h"

#include <ctype.h>
#include <string>

namespace {

static void diagToErrlog(void* /*user*/, const epicsYamlDiag* d)
{
    if (!d) return;
    const char* sev = (d->severity == epicsYaml_Severity_Warning) ? "warning" :
                      (d->severity == epicsYaml_Severity_Info) ? "info" : "error";
    errlogPrintf("%s:%u:%u: %s: %s\n",
                 d->filename ? d->filename : "<yaml>",
                 d->line, d->column,
                 sev,
                 d->message ? d->message : "");
}

static bool isTokenSafe(const std::string& s)
{
    if (s.empty()) return false;
    for (char c : s) {
        if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == ':' || c == '.'))
            return false;
    }
    return true;
}

static void emitQuoted(FILE* fp, const std::string& s)
{
    fputc('"', fp);
    for (char c : s) {
        if (c == '"' || c == '\\') fputc('\\', fp);
        fputc(c, fp);
    }
    fputc('"', fp);
}

static const epicsYamlNode* requireMapKey(const epicsYamlNode* m, const char* key)
{
    const epicsYamlNode* v = epicsYamlNodeMapFind(m, key);
    return v;
}

static std::string getStringOrEmpty(const epicsYamlNode* n)
{
    const char* s = nullptr;
    if (!n) return std::string();
    if (epicsYamlNodeGetString(n, &s) == 0 && s) return std::string(s);
    return std::string();
}

static bool getBoolOrDefault(const epicsYamlNode* n, bool defval)
{
    int b = 0;
    if (!n) return defval;
    if (epicsYamlNodeGetBool(n, &b) == 0) return b != 0;
    return defval;
}

static void emitLegacyLines(FILE* fp, const epicsYamlNode* seq)
{
    const size_t N = epicsYamlNodeSeqSize(seq);
    for (size_t i = 0; i < N; ++i) {
        const epicsYamlNode* ln = epicsYamlNodeSeqAt(seq, i);
        const char* s = nullptr;
        if (!ln || epicsYamlNodeGetString(ln, &s) != 0 || !s) continue;
        fputs(s, fp);
        fputc('\n', fp);
    }
}

static void emitCommaSepQuotedList(FILE* fp, const epicsYamlNode* seq)
{
    const size_t N = epicsYamlNodeSeqSize(seq);
    for (size_t i = 0; i < N; ++i) {
        if (i) fputs(", ", fp);
        const epicsYamlNode* it = epicsYamlNodeSeqAt(seq, i);
        std::string s = getStringOrEmpty(it);
        emitQuoted(fp, s);
    }
}

static void emitUAG(FILE* fp, const epicsYamlNode* uag)
{
    const epicsYamlNode* nameN = requireMapKey(uag, "name");
    std::string name = getStringOrEmpty(nameN);
    fputs("UAG(", fp);
    emitQuoted(fp, name);
    fputs(") ", fp);

    const epicsYamlNode* usersN = requireMapKey(uag, "users");
    if (usersN && epicsYamlNodeKind(usersN) == epicsYaml_Seq) {
        fputs("{ ", fp);
        emitCommaSepQuotedList(fp, usersN);
        fputs(" }", fp);
    }
    fputc('\n', fp);
}

static void emitHAG(FILE* fp, const epicsYamlNode* hag)
{
    const epicsYamlNode* nameN = requireMapKey(hag, "name");
    std::string name = getStringOrEmpty(nameN);
    fputs("HAG(", fp);
    emitQuoted(fp, name);
    fputs(") ", fp);

    const epicsYamlNode* hostsN = requireMapKey(hag, "hosts");
    if (hostsN && epicsYamlNodeKind(hostsN) == epicsYaml_Seq) {
        fputs("{ ", fp);
        emitCommaSepQuotedList(fp, hostsN);
        fputs(" }", fp);
    }
    fputc('\n', fp);
}

static void emitRule(FILE* fp, const epicsYamlNode* rule)
{
    // level
    epicsInt64 lvl = 0;
    const epicsYamlNode* lvlN = requireMapKey(rule, "level");
    (void)epicsYamlNodeGetInt64(lvlN, &lvl);

    // access
    std::string access = getStringOrEmpty(requireMapKey(rule, "access"));
    if (access.empty()) access = "NONE";

    bool trap = getBoolOrDefault(requireMapKey(rule, "trapwrite"), false);

    fputs("    RULE(", fp);
    fprintf(fp, "%lld", (long long)lvl);
    fputs(", ", fp);
    fputs(access.c_str(), fp);
    if (trap) {
        fputs(", TRAPWRITE", fp);
    }
    fputs(")", fp);

    const epicsYamlNode* uags = requireMapKey(rule, "uags");
    const epicsYamlNode* hags = requireMapKey(rule, "hags");
    const epicsYamlNode* calc = requireMapKey(rule, "calc");
    bool hasBody = (uags && epicsYamlNodeKind(uags) == epicsYaml_Seq && epicsYamlNodeSeqSize(uags) > 0)
                || (hags && epicsYamlNodeKind(hags) == epicsYaml_Seq && epicsYamlNodeSeqSize(hags) > 0)
                || (calc && epicsYamlNodeKind(calc) == epicsYaml_String);

    if (!hasBody) {
        fputc('\n', fp);
        return;
    }

    fputs(" {\n", fp);

    if (uags && epicsYamlNodeKind(uags) == epicsYaml_Seq && epicsYamlNodeSeqSize(uags) > 0) {
        fputs("        UAG(", fp);
        emitCommaSepQuotedList(fp, uags);
        fputs(")\n", fp);
    }
    if (hags && epicsYamlNodeKind(hags) == epicsYaml_Seq && epicsYamlNodeSeqSize(hags) > 0) {
        fputs("        HAG(", fp);
        emitCommaSepQuotedList(fp, hags);
        fputs(")\n", fp);
    }
    if (calc && epicsYamlNodeKind(calc) == epicsYaml_String) {
        std::string expr = getStringOrEmpty(calc);
        fputs("        CALC(", fp);
        emitQuoted(fp, expr);
        fputs(")\n", fp);
    }

    fputs("    }\n", fp);
}

static void emitASG(FILE* fp, const epicsYamlNode* asg)
{
    std::string name = getStringOrEmpty(requireMapKey(asg, "name"));
    fputs("ASG(", fp);
    emitQuoted(fp, name);
    fputs(") {\n", fp);

    // optional INP* mappings
    const epicsYamlNode* inps = requireMapKey(asg, "inps");
    if (inps && epicsYamlNodeKind(inps) == epicsYaml_Map) {
        const size_t N = epicsYamlNodeMapSize(inps);
        for (size_t i = 0; i < N; ++i) {
            const char* k = epicsYamlNodeMapKeyAt(inps, i);
            const epicsYamlNode* v = epicsYamlNodeMapValueAt(inps, i);
            if (!k || !v) continue;
            std::string key(k);
            std::string val = getStringOrEmpty(v);
            if (!isTokenSafe(key)) continue;
            fputs("    ", fp);
            fputs(key.c_str(), fp);
            fputs("(", fp);
            emitQuoted(fp, val);
            fputs(")\n", fp);
        }
    }

    const epicsYamlNode* rules = requireMapKey(asg, "rules");
    if (rules && epicsYamlNodeKind(rules) == epicsYaml_Seq) {
        const size_t N = epicsYamlNodeSeqSize(rules);
        for (size_t i = 0; i < N; ++i) {
            const epicsYamlNode* rule = epicsYamlNodeSeqAt(rules, i);
            if (!rule || epicsYamlNodeKind(rule) != epicsYaml_Map) continue;
            emitRule(fp, rule);
        }
    }

    fputs("}\n", fp);
}

} // namespace

extern "C" {

// Render epics.acf YAML into canonical legacy ACF text.
// Returns 0 on success, non-zero on error.
int epicsStdCall epicsAsYamlToLegacyACF(const char* filename, FILE* out)
{
    if (!filename || !out) return -1;
    epicsYamlLimits lim{};
    lim.maxFileBytes = 1024u * 1024u;
    lim.maxDepth = 64u;
    lim.maxNodes = 200000u;
    lim.maxLineBytes = 16384u;

    std::unique_ptr<epicsYamlDocument, void(*)(epicsYamlDocument*)> doc(
        epicsYamlParseFile(filename, &lim, diagToErrlog, nullptr),
        epicsYamlDocFree);
    if (!doc) return -1;
    const epicsYamlNode* root = epicsYamlDocRoot(doc.get());
    if (!root || epicsYamlNodeKind(root) != epicsYaml_Map) {
        errlogPrintf("%s: root must be a mapping\n", filename);
        return -1;
    }

    const epicsYamlNode* kindN = epicsYamlNodeMapFind(root, "kind");
    if (kindN && epicsYamlNodeKind(kindN) == epicsYaml_String) {
        std::string kind = getStringOrEmpty(kindN);
        if (!kind.empty() && kind != "epics.acf") {
            errlogPrintf("%s: kind must be epics.acf (got '%s')\n", filename, kind.c_str());
            return -1;
        }
    }

    // escape hatch: legacy lines
    const epicsYamlNode* legacy = epicsYamlNodeMapFind(root, "legacy");
    if (legacy && epicsYamlNodeKind(legacy) == epicsYaml_Seq) {
        emitLegacyLines(out, legacy);
        return 0;
    }

    const epicsYamlNode* uags = epicsYamlNodeMapFind(root, "uags");
    if (uags && epicsYamlNodeKind(uags) == epicsYaml_Seq) {
        const size_t N = epicsYamlNodeSeqSize(uags);
        for (size_t i = 0; i < N; ++i) {
            const epicsYamlNode* uag = epicsYamlNodeSeqAt(uags, i);
            if (!uag || epicsYamlNodeKind(uag) != epicsYaml_Map) continue;
            emitUAG(out, uag);
        }
        fputc('\n', out);
    }

    const epicsYamlNode* hags = epicsYamlNodeMapFind(root, "hags");
    if (hags && epicsYamlNodeKind(hags) == epicsYaml_Seq) {
        const size_t N = epicsYamlNodeSeqSize(hags);
        for (size_t i = 0; i < N; ++i) {
            const epicsYamlNode* hag = epicsYamlNodeSeqAt(hags, i);
            if (!hag || epicsYamlNodeKind(hag) != epicsYaml_Map) continue;
            emitHAG(out, hag);
        }
        fputc('\n', out);
    }

    const epicsYamlNode* asgs = epicsYamlNodeMapFind(root, "asgs");
    if (!asgs || epicsYamlNodeKind(asgs) != epicsYaml_Seq) {
        errlogPrintf("%s: missing required 'asgs' list\n", filename);
        return -1;
    }
    {
        const size_t N = epicsYamlNodeSeqSize(asgs);
        for (size_t i = 0; i < N; ++i) {
            const epicsYamlNode* asg = epicsYamlNodeSeqAt(asgs, i);
            if (!asg || epicsYamlNodeKind(asg) != epicsYaml_Map) continue;
            emitASG(out, asg);
            fputc('\n', out);
        }
    }

    return 0;
}

} // extern "C"
