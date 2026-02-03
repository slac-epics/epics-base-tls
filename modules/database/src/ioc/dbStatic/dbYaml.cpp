// SPDX-License-Identifier: EPICS

#include "epicsYaml.h"

#include "epicsString.h"

#include <ctype.h>
#include <stdio.h>
#include <string>

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

static void emitDbQuoted(FILE* fp, const std::string& s)
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

static bool endsWithNoCase(const std::string& s, const char* suf)
{
    size_t n = s.size(), m = strlen(suf);
    if (m > n) return false;
    for (size_t i = 0; i < m; ++i) {
        if (tolower((unsigned char)s[n - m + i]) != tolower((unsigned char)suf[i])) return false;
    }
    return true;
}

static std::string guessKindFromFilename(const std::string& fn)
{
    // handle double-extension
    if (endsWithNoCase(fn, ".dbd.yaml") || endsWithNoCase(fn, ".dbd.yml")) return "epics.dbd";
    if (endsWithNoCase(fn, ".db.yaml") || endsWithNoCase(fn, ".db.yml")) return "epics.db";
    return std::string();
}

} // namespace

extern "C" {

// Render epics.db/epics.dbd YAML into canonical legacy .db/.dbd text.
// Returns 0 on success, non-zero on error.
int epicsStdCall epicsDbYamlToLegacy(const char* filename, FILE* out)
{
    if (!filename || !out) return -1;

    epicsYamlLimits lim{};
    lim.maxFileBytes = 4u * 1024u * 1024u;
    lim.maxDepth = 64u;
    lim.maxNodes = 400000u;
    lim.maxLineBytes = 16384u;

    epicsYamlDocument* doc = epicsYamlParseFile(filename, &lim, diagToStderr, nullptr);
    if (!doc) return -1;

    const epicsYamlNode* root = epicsYamlDocRoot(doc);
    if (!root || epicsYamlNodeKind(root) != epicsYaml_Map) {
        fprintf(stderr, "%s: root must be a mapping\n", filename);
        epicsYamlDocFree(doc);
        return -1;
    }

    std::string kind = getStringOrEmpty(epicsYamlNodeMapFind(root, "kind"));
    if (kind.empty()) kind = guessKindFromFilename(filename);
    if (kind != "epics.db" && kind != "epics.dbd") {
        fprintf(stderr, "%s: kind must be epics.db or epics.dbd (got '%s')\n", filename, kind.c_str());
        epicsYamlDocFree(doc);
        return -1;
    }

    const epicsYamlNode* legacy = epicsYamlNodeMapFind(root, "legacy");
    if (legacy && epicsYamlNodeKind(legacy) == epicsYaml_Seq) {
        emitLegacyLines(out, legacy);
        epicsYamlDocFree(doc);
        return 0;
    }

    // DBD: minimal structured support (include/registrars) + allow future expansion.
    if (kind == "epics.dbd") {
        const epicsYamlNode* inc = epicsYamlNodeMapFind(root, "include");
        if (inc && epicsYamlNodeKind(inc) == epicsYaml_Seq) {
            for (size_t i = 0, N = epicsYamlNodeSeqSize(inc); i < N; ++i) {
                std::string f = getStringOrEmpty(epicsYamlNodeSeqAt(inc, i));
                if (f.empty()) continue;
                fputs("include ", out);
                emitDbQuoted(out, f);
                fputc('\n', out);
            }
            fputc('\n', out);
        }

        const epicsYamlNode* regs = epicsYamlNodeMapFind(root, "registrars");
        if (regs && epicsYamlNodeKind(regs) == epicsYaml_Seq) {
            for (size_t i = 0, N = epicsYamlNodeSeqSize(regs); i < N; ++i) {
                std::string r = getStringOrEmpty(epicsYamlNodeSeqAt(regs, i));
                if (r.empty()) continue;
                fputs("registrar(", out);
                emitDbQuoted(out, r);
                fputs(")\n", out);
            }
            fputc('\n', out);
        }

        epicsYamlDocFree(doc);
        return 0;
    }

    // DB: records[]
    const epicsYamlNode* records = epicsYamlNodeMapFind(root, "records");
    if (!records || epicsYamlNodeKind(records) != epicsYaml_Seq) {
        fprintf(stderr, "%s: missing required 'records' list\n", filename);
        epicsYamlDocFree(doc);
        return -1;
    }

    for (size_t ri = 0, RN = epicsYamlNodeSeqSize(records); ri < RN; ++ri) {
        const epicsYamlNode* rec = epicsYamlNodeSeqAt(records, ri);
        if (!rec || epicsYamlNodeKind(rec) != epicsYaml_Map) continue;

        std::string type = getStringOrEmpty(epicsYamlNodeMapFind(rec, "type"));
        std::string name = getStringOrEmpty(epicsYamlNodeMapFind(rec, "name"));
        if (type.empty() || name.empty()) {
            fprintf(stderr, "%s: record missing type/name\n", filename);
            epicsYamlDocFree(doc);
            return -1;
        }

        fputs("record(", out);
        fputs(type.c_str(), out);
        fputs(", ", out);
        emitDbQuoted(out, name);
        fputs(") {\n", out);

        const epicsYamlNode* fields = epicsYamlNodeMapFind(rec, "fields");
        if (fields && epicsYamlNodeKind(fields) == epicsYaml_Map) {
            for (size_t fi = 0, FN = epicsYamlNodeMapSize(fields); fi < FN; ++fi) {
                const char* k = epicsYamlNodeMapKeyAt(fields, fi);
                const epicsYamlNode* v = epicsYamlNodeMapValueAt(fields, fi);
                if (!k || !v) continue;
                std::string val = getStringOrEmpty(v);
                fputs("    field(", out);
                emitDbQuoted(out, k);
                fputs(", ", out);
                emitDbQuoted(out, val);
                fputs(")\n", out);
            }
        }

        const epicsYamlNode* info = epicsYamlNodeMapFind(rec, "info");
        if (info && epicsYamlNodeKind(info) == epicsYaml_Map) {
            for (size_t ii = 0, IN = epicsYamlNodeMapSize(info); ii < IN; ++ii) {
                const char* k = epicsYamlNodeMapKeyAt(info, ii);
                const epicsYamlNode* v = epicsYamlNodeMapValueAt(info, ii);
                if (!k || !v) continue;
                std::string val = getStringOrEmpty(v);
                fputs("    info(", out);
                emitDbQuoted(out, k);
                fputs(", ", out);
                emitDbQuoted(out, val);
                fputs(")\n", out);
            }
        }

        fputs("}\n\n", out);
    }

    epicsYamlDocFree(doc);
    return 0;
}

} // extern "C"
