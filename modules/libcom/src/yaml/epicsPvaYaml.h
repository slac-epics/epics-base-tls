/*
 * SPDX-License-Identifier: EPICS
 *
 * PVA client/server configuration loaded from EPICS YAML.
 *
 * This module parses a nested, YAML-friendly schema and produces an
 * equivalent set of environment-like key/value settings.
 */

#ifndef INC_epicsPvaYaml_H
#define INC_epicsPvaYaml_H

#include <stddef.h>

#include "libComAPI.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct epicsPvaYamlKVList epicsPvaYamlKVList;

/* Load client/server config.
 * If filename is NULL, the default XDG-based location is used.
 * Returns NULL on error.
 */
LIBCOM_API epicsPvaYamlKVList* epicsStdCall epicsPvaYamlLoadClient(const char* filename);
LIBCOM_API epicsPvaYamlKVList* epicsStdCall epicsPvaYamlLoadServer(const char* filename);

LIBCOM_API void epicsStdCall epicsPvaYamlKVFree(epicsPvaYamlKVList* kv);

LIBCOM_API size_t epicsStdCall epicsPvaYamlKVSize(const epicsPvaYamlKVList* kv);
LIBCOM_API const char* epicsStdCall epicsPvaYamlKVKeyAt(const epicsPvaYamlKVList* kv, size_t idx);
LIBCOM_API const char* epicsStdCall epicsPvaYamlKVValueAt(const epicsPvaYamlKVList* kv, size_t idx);

/* Apply settings to process environment.
 * overwrite=0 keeps existing variables.
 * Returns 0 on success.
 */
LIBCOM_API int epicsStdCall epicsPvaYamlApplyEnv(const epicsPvaYamlKVList* kv, int overwrite);

/* Default filenames following XDG-style locations.
 * Returned strings are allocated with malloc() and must be freed by caller.
 */
LIBCOM_API char* epicsStdCall epicsPvaYamlDefaultClientPath(void);
LIBCOM_API char* epicsStdCall epicsPvaYamlDefaultServerPath(void);

#ifdef __cplusplus
}
#endif

#endif /* INC_epicsPvaYaml_H */
