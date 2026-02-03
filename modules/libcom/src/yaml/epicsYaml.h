/*
 * SPDX-License-Identifier: EPICS
 *
 * Minimal, self-contained YAML subset parser for EPICS.
 *
 * No external YAML library is used.
 * The supported grammar is intentionally restricted (see README_YAML.md).
 */

#ifndef INC_epicsYaml_H
#define INC_epicsYaml_H

#include <stdio.h>

#include "libComAPI.h"
#include "epicsTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct epicsYamlDocument epicsYamlDocument;
typedef struct epicsYamlNode epicsYamlNode;

typedef enum {
    epicsYaml_Severity_Info = 0,
    epicsYaml_Severity_Warning = 1,
    epicsYaml_Severity_Error = 2,
} epicsYamlSeverity;

typedef struct {
    const char* filename;
    unsigned line;      /* 1-based */
    unsigned column;    /* 1-based */
    epicsYamlSeverity severity;
    const char* message; /* null-terminated; owned by callee only for duration of callback */
} epicsYamlDiag;

typedef void (*epicsYamlDiagFn)(void* user, const epicsYamlDiag* diag);

typedef enum {
    epicsYaml_Null = 0,
    epicsYaml_Bool,
    epicsYaml_Int,
    epicsYaml_Double,
    epicsYaml_String,
    epicsYaml_Map,
    epicsYaml_Seq,
} epicsYamlKind;

typedef struct {
    size_t maxFileBytes;    /* default: 1 MiB if 0 */
    unsigned maxDepth;      /* default: 64 if 0 */
    size_t maxNodes;        /* default: 200000 if 0 */
    size_t maxLineBytes;    /* default: 16384 if 0 */
} epicsYamlLimits;

/* Returns 1 if filename ends with .yaml or .yml (case-insensitive), else 0 */
LIBCOM_API int epicsStdCall epicsYamlIsYamlFilename(const char* filename);

/* Parse a YAML file into a document tree.
 * On success returns non-NULL and sets *outDoc.
 * On failure returns NULL and sets *outDoc to NULL.
 */
LIBCOM_API epicsYamlDocument* epicsStdCall epicsYamlParseFile(
    const char* filename,
    const epicsYamlLimits* limits,
    epicsYamlDiagFn diagFn,
    void* diagUser);

/* Parse YAML from an already-open FILE*.
 * The stream is read from its current position.
 * The stream is not closed.
 * displayName is used in diagnostics (may be NULL).
 */
LIBCOM_API epicsYamlDocument* epicsStdCall epicsYamlParseFP(
    FILE* fp,
    const char* displayName,
    const epicsYamlLimits* limits,
    epicsYamlDiagFn diagFn,
    void* diagUser);

LIBCOM_API void epicsStdCall epicsYamlDocFree(epicsYamlDocument* doc);

LIBCOM_API const epicsYamlNode* epicsStdCall epicsYamlDocRoot(const epicsYamlDocument* doc);

LIBCOM_API epicsYamlKind epicsStdCall epicsYamlNodeKind(const epicsYamlNode* node);

/* Scalar accessors: return 0 on success, non-zero on type mismatch */
LIBCOM_API int epicsStdCall epicsYamlNodeGetBool(const epicsYamlNode* node, int* out);
LIBCOM_API int epicsStdCall epicsYamlNodeGetInt64(const epicsYamlNode* node, epicsInt64* out);
LIBCOM_API int epicsStdCall epicsYamlNodeGetDouble(const epicsYamlNode* node, double* out);
LIBCOM_API int epicsStdCall epicsYamlNodeGetString(const epicsYamlNode* node, const char** out);

/* Map access */
LIBCOM_API size_t epicsStdCall epicsYamlNodeMapSize(const epicsYamlNode* node);
LIBCOM_API const char* epicsStdCall epicsYamlNodeMapKeyAt(const epicsYamlNode* node, size_t idx);
LIBCOM_API const epicsYamlNode* epicsStdCall epicsYamlNodeMapValueAt(const epicsYamlNode* node, size_t idx);
LIBCOM_API const epicsYamlNode* epicsStdCall epicsYamlNodeMapFind(const epicsYamlNode* node, const char* key);

/* Sequence access */
LIBCOM_API size_t epicsStdCall epicsYamlNodeSeqSize(const epicsYamlNode* node);
LIBCOM_API const epicsYamlNode* epicsStdCall epicsYamlNodeSeqAt(const epicsYamlNode* node, size_t idx);

/* Optional helpers */
LIBCOM_API const char* epicsStdCall epicsYamlNodeFilename(const epicsYamlNode* node);
LIBCOM_API unsigned epicsStdCall epicsYamlNodeLine(const epicsYamlNode* node);
LIBCOM_API unsigned epicsStdCall epicsYamlNodeColumn(const epicsYamlNode* node);

#ifdef __cplusplus
}
#endif

#endif /* INC_epicsYaml_H */
