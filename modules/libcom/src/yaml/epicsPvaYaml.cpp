// SPDX-License-Identifier: EPICS

#include "epicsPvaYaml.h"

#include "epicsYaml.h"

#include "envDefs.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include <string>
#include <utility>
#include <vector>

struct KVList {
    std::vector<std::pair<std::string, std::string>> kv;
};

struct epicsPvaYamlKVList {
    KVList kv;
};

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

static bool getBoolOrDefault(const epicsYamlNode* n, bool def)
{
    int b = 0;
    if (!n) return def;
    if (epicsYamlNodeGetBool(n, &b) == 0) return b != 0;
    return def;
}

static std::string joinSeqStrings(const epicsYamlNode* seq)
{
    std::string out;
    if (!seq || epicsYamlNodeKind(seq) != epicsYaml_Seq) return out;
    for (size_t i = 0, N = epicsYamlNodeSeqSize(seq); i < N; ++i) {
        std::string s = getStringOrEmpty(epicsYamlNodeSeqAt(seq, i));
        if (s.empty()) continue;
        if (!out.empty()) out.push_back(' ');
        out += s;
    }
    return out;
}

static std::string xdgConfigHome()
{
    const char* xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) return std::string(xdg);
    const char* home = getenv("HOME");
    if (home && *home) return std::string(home) + "/.config";
    return std::string();
}

static char* defaultPath(const char* leaf)
{
    std::string base = xdgConfigHome();
    if (base.empty()) return nullptr;
    std::string full = base + "/pva/1.5/" + leaf;
    char* ret = (char*)malloc(full.size() + 1);
    if (!ret) return nullptr;
    memcpy(ret, full.c_str(), full.size() + 1);
    return ret;
}

static void mergeEnvMap(KVList& out, const epicsYamlNode* env)
{
    if (!env || epicsYamlNodeKind(env) != epicsYaml_Map) return;
    for (size_t i = 0, N = epicsYamlNodeMapSize(env); i < N; ++i) {
        const char* k = epicsYamlNodeMapKeyAt(env, i);
        const epicsYamlNode* v = epicsYamlNodeMapValueAt(env, i);
        if (!k || !v) continue;
        out.kv.emplace_back(std::string(k), getStringOrEmpty(v));
    }
}

static epicsPvaYamlKVList* loadCommon(const char* filename, const char* kindExpected)
{
    char* def = nullptr;
    if (!filename) {
        def = defaultPath((strcmp(kindExpected, "epics.pva.client") == 0) ? "client.yaml" : "server.yaml");
        filename = def;
    }
    if (!filename) return nullptr;

    epicsYamlLimits lim{};
    lim.maxFileBytes = 1024u * 1024u;
    lim.maxDepth = 64u;
    lim.maxNodes = 200000u;
    lim.maxLineBytes = 16384u;

    epicsYamlDocument* doc = epicsYamlParseFile(filename, &lim, diagToStderr, nullptr);
    free(def);
    if (!doc) return nullptr;
    const epicsYamlNode* root = epicsYamlDocRoot(doc);
    if (!root || epicsYamlNodeKind(root) != epicsYaml_Map) {
        epicsYamlDocFree(doc);
        return nullptr;
    }

    std::string kind = getStringOrEmpty(epicsYamlNodeMapFind(root, "kind"));
    if (!kind.empty() && kind != kindExpected) {
        epicsYamlDocFree(doc);
        return nullptr;
    }

    KVList out;

    // canonical nested schema: top-level 'epics'
    const epicsYamlNode* epics = epicsYamlNodeMapFind(root, "epics");
    if (epics && epicsYamlNodeKind(epics) == epicsYaml_Map) {
        const epicsYamlNode* addr = epicsYamlNodeMapFind(epics, "addr_list");
        if (addr && epicsYamlNodeKind(addr) == epicsYaml_Map) {
            std::string names = joinSeqStrings(epicsYamlNodeMapFind(addr, "names"));
            if (!names.empty()) {
                out.kv.emplace_back("EPICS_PVA_ADDR_LIST", names);
            }
            bool aut = getBoolOrDefault(epicsYamlNodeMapFind(addr, "auto"), true);
            out.kv.emplace_back("EPICS_PVA_AUTO_ADDR_LIST", aut ? "YES" : "NO");
        }

        const epicsYamlNode* ns = epicsYamlNodeMapFind(epics, "name_servers");
        if (ns && epicsYamlNodeKind(ns) == epicsYaml_Map) {
            std::string names = joinSeqStrings(epicsYamlNodeMapFind(ns, "names"));
            if (!names.empty()) {
                out.kv.emplace_back("EPICS_PVA_NAME_SERVERS", names);
            }
        }

        const epicsYamlNode* tls = epicsYamlNodeMapFind(epics, "tls");
        if (tls && epicsYamlNodeKind(tls) == epicsYaml_Map) {
            std::string keychain = getStringOrEmpty(epicsYamlNodeMapFind(tls, "keychain"));
            if (!keychain.empty()) {
                if (strcmp(kindExpected, "epics.pva.client") == 0)
                    out.kv.emplace_back("EPICS_PVA_TLS_KEYCHAIN", keychain);
                else
                    out.kv.emplace_back("EPICS_PVAS_TLS_KEYCHAIN", keychain);
            }
        }
    }

    // compatibility: top-level env map merged last
    mergeEnvMap(out, epicsYamlNodeMapFind(root, "env"));

    epicsYamlDocFree(doc);

    return new epicsPvaYamlKVList{std::move(out)};
}

} // namespace

extern "C" {

epicsPvaYamlKVList* epicsStdCall epicsPvaYamlLoadClient(const char* filename)
{
    return loadCommon(filename, "epics.pva.client");
}

epicsPvaYamlKVList* epicsStdCall epicsPvaYamlLoadServer(const char* filename)
{
    return loadCommon(filename, "epics.pva.server");
}

void epicsStdCall epicsPvaYamlKVFree(epicsPvaYamlKVList* kv)
{
    delete kv;
}

size_t epicsStdCall epicsPvaYamlKVSize(const epicsPvaYamlKVList* kv)
{
    return kv ? kv->kv.kv.size() : 0u;
}

const char* epicsStdCall epicsPvaYamlKVKeyAt(const epicsPvaYamlKVList* kv, size_t idx)
{
    if (!kv || idx >= kv->kv.kv.size()) return nullptr;
    return kv->kv.kv[idx].first.c_str();
}

const char* epicsStdCall epicsPvaYamlKVValueAt(const epicsPvaYamlKVList* kv, size_t idx)
{
    if (!kv || idx >= kv->kv.kv.size()) return nullptr;
    return kv->kv.kv[idx].second.c_str();
}

int epicsStdCall epicsPvaYamlApplyEnv(const epicsPvaYamlKVList* kv, int overwrite)
{
    if (!kv) return -1;
    for (const auto& it : kv->kv.kv) {
        const char* k = it.first.c_str();
        const char* v = it.second.c_str();
        if (!overwrite) {
            const char* cur = getenv(k);
            if (cur && *cur) continue;
        }
        epicsEnvSet(k, v);
    }
    return 0;
}

char* epicsStdCall epicsPvaYamlDefaultClientPath(void)
{
    return defaultPath("client.yaml");
}

char* epicsStdCall epicsPvaYamlDefaultServerPath(void)
{
    return defaultPath("server.yaml");
}

} // extern "C"
