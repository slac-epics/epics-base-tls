// SPDX-License-Identifier: EPICS

#include "epicsYaml.h"

#include <stdio.h>
#include <string>
#include <vector>

namespace {

static void diagToStderr(void* /*user*/, const epicsYamlDiag* d)
{
    if (!d) return;
    const char* sev = (d->severity == epicsYaml_Severity_Warning) ? "warning" :
                      (d->severity == epicsYaml_Severity_Info) ? "info" : "error";
    fprintf(stderr, "%s:%u:%u: %s: %s\n",
            d->filename ? d->filename : "<yaml>",
            d->line, d->column,
            sev,
            d->message ? d->message : "");
}

static std::string getStringOrEmpty(const epicsYamlNode* n)
{
    const char* s = nullptr;
    if (!n) return std::string();
    if (epicsYamlNodeGetString(n, &s) == 0 && s) return std::string(s);
    return std::string();
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

static std::vector<std::string> orderedKeysFromFirstMap(const epicsYamlNode* seq)
{
    std::vector<std::string> keys;
    if (!seq || epicsYamlNodeKind(seq) != epicsYaml_Seq || epicsYamlNodeSeqSize(seq) == 0) return keys;
    const epicsYamlNode* first = epicsYamlNodeSeqAt(seq, 0);
    if (!first || epicsYamlNodeKind(first) != epicsYaml_Map) return keys;
    for (size_t i = 0, N = epicsYamlNodeMapSize(first); i < N; ++i) {
        const char* k = epicsYamlNodeMapKeyAt(first, i);
        if (k) keys.emplace_back(k);
    }
    return keys;
}

} // namespace

extern "C" {

// Render epics.substitutions YAML into canonical legacy .substitutions text.
// Returns 0 on success, non-zero on error.
int epicsStdCall epicsSubstYamlToLegacy(const char* displayName, FILE* in, FILE* out)
{
    if (!in || !out) return -1;

    epicsYamlLimits lim{};
    lim.maxFileBytes = 2u * 1024u * 1024u;
    lim.maxDepth = 64u;
    lim.maxNodes = 200000u;
    lim.maxLineBytes = 16384u;

    epicsYamlDocument* doc = epicsYamlParseFP(in, displayName, &lim, diagToStderr, nullptr);
    if (!doc) return -1;
    const epicsYamlNode* root = epicsYamlDocRoot(doc);
    if (!root || epicsYamlNodeKind(root) != epicsYaml_Map) {
        fprintf(stderr, "%s: root must be a mapping\n", displayName ? displayName : "<yaml>");
        epicsYamlDocFree(doc);
        return -1;
    }

    std::string kind = getStringOrEmpty(epicsYamlNodeMapFind(root, "kind"));
    if (!kind.empty() && kind != "epics.substitutions") {
        fprintf(stderr, "%s: kind must be epics.substitutions (got '%s')\n",
                displayName ? displayName : "<yaml>", kind.c_str());
        epicsYamlDocFree(doc);
        return -1;
    }

    const epicsYamlNode* legacy = epicsYamlNodeMapFind(root, "legacy");
    if (legacy && epicsYamlNodeKind(legacy) == epicsYaml_Seq) {
        emitLegacyLines(out, legacy);
        epicsYamlDocFree(doc);
        return 0;
    }

    const epicsYamlNode* templates = epicsYamlNodeMapFind(root, "templates");
    if (!templates || epicsYamlNodeKind(templates) != epicsYaml_Seq) {
        fprintf(stderr, "%s: missing required 'templates' list\n", displayName ? displayName : "<yaml>");
        epicsYamlDocFree(doc);
        return -1;
    }

    for (size_t ti = 0, TN = epicsYamlNodeSeqSize(templates); ti < TN; ++ti) {
        const epicsYamlNode* t = epicsYamlNodeSeqAt(templates, ti);
        if (!t || epicsYamlNodeKind(t) != epicsYaml_Map) continue;

        std::string file = getStringOrEmpty(epicsYamlNodeMapFind(t, "file"));
        if (file.empty()) {
            fprintf(stderr, "%s: template missing 'file'\n", displayName ? displayName : "<yaml>");
            epicsYamlDocFree(doc);
            return -1;
        }

        const epicsYamlNode* subs = epicsYamlNodeMapFind(t, "substitutions");
        if (!subs || epicsYamlNodeKind(subs) != epicsYaml_Seq || epicsYamlNodeSeqSize(subs) == 0) {
            continue;
        }

        auto keys = orderedKeysFromFirstMap(subs);
        if (keys.empty()) {
            fprintf(stderr, "%s: substitutions entry must be a mapping\n", displayName ? displayName : "<yaml>");
            epicsYamlDocFree(doc);
            return -1;
        }

        fputs("file ", out);
        emitQuoted(out, file);
        fputs(" {\n", out);

        fputs("    pattern { ", out);
        for (size_t ki = 0; ki < keys.size(); ++ki) {
            if (ki) fputs(", ", out);
            fputs(keys[ki].c_str(), out);
        }
        fputs(" }\n", out);

        for (size_t si = 0, SN = epicsYamlNodeSeqSize(subs); si < SN; ++si) {
            const epicsYamlNode* m = epicsYamlNodeSeqAt(subs, si);
            if (!m || epicsYamlNodeKind(m) != epicsYaml_Map) continue;

            fputs("    { ", out);
            for (size_t ki = 0; ki < keys.size(); ++ki) {
                if (ki) fputs(", ", out);
                const epicsYamlNode* v = epicsYamlNodeMapFind(m, keys[ki].c_str());
                emitQuoted(out, getStringOrEmpty(v));
            }
            fputs(" }\n", out);
        }

        fputs("}\n\n", out);
    }

    epicsYamlDocFree(doc);
    return 0;
}

} // extern "C"
