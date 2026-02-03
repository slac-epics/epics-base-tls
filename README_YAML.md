# YAML-ification Notes (epics-base)

This document captures an initial inventory of EPICS-related configuration/data file formats, plus proposed naming conventions, default locations, and an architectural direction for a reusable YAML parser frontend.

## Goal

Allow *all* supported file types to be expressed in either:

* the existing legacy format (current behavior), or
* a YAML representation

…with minimal duplication of parsing logic, and a path to add future YAML-based formats.

## Inventory: known formats and their current entry points

### EPICS Database and DBD

Legacy conventions:

* Record instance files: `*.db`
* DBD files: `*.dbd`

IOC entry points:

* `dbLoadDatabase()` and `dbLoadRecords()` in `modules/database/src/ioc/db/dbAccess.c`
* both call `dbReadDatabase()` in `modules/database/src/ioc/dbStatic/dbLexRoutines.c`

Legacy grammar implementation:

* `modules/database/src/ioc/dbStatic/dbYacc.y`
* `modules/database/src/ioc/dbStatic/dbLex.l`

YAML constraints to capture:

* Records: type, name, `field()` assignments, `info()` tags, aliases, etc.
* Macro expansion semantics (`subs` argument, macLib behavior)
* Include/search paths and include-like constructs

### dbLoadTemplate substitution files and template DB fragments

Legacy conventions:

* Substitution files: `*.substitutions`
* Template DB fragments are often named `*.template` but use DB syntax

IOC entry point:

* `dbLoadTemplate()` declared in `modules/database/src/ioc/dbtemplate/dbLoadTemplate.h`

Legacy grammar implementation:

* `modules/database/src/ioc/dbtemplate/dbLoadTemplate.y`
* `modules/database/src/ioc/dbtemplate/dbLoadTemplate_lex.l`

Host tool:

* `msi` in `modules/database/src/ioc/dbtemplate/msi.cpp` (macro substitution/include tool)
* docs: `modules/database/src/ioc/dbtemplate/msi.md`

YAML constraints to capture:

* Multiple templates, patterns/blocks, legacy syntax variants
* Include path semantics and macro scoping/overrides

### Access Security configuration (ACF)

Legacy convention:

* `*.acf`

IOC entry points:

* `asSetFilename()` / `asInit()` in `modules/database/src/ioc/as/asDbLib.c`
* iocsh registration: `modules/database/src/ioc/as/asIocRegister.c`

Legacy grammar implementation:

* `modules/libcom/src/as/asLib.y`
* `modules/libcom/src/as/asLib_lex.l`
* supporting routines: `modules/libcom/src/as/asLibRoutines.c`

YAML precedent outside this repo (pvxs):

* `../pvxs/test/testioc.tls.acf` vs `../pvxs/test/testioc.tls.acf.yaml`
* `../pvxs/certs/pvacms.cpp` already switches behavior based on `.acf` vs `.yaml`/`.yml`

YAML constraints to capture:

* UAG/HAG/ASG/RULE definitions
* trapwrite, calc expressions, INP* references (where used), method/auth/authority lists

### PVA gateway configuration (p4p)

In `../p4p` the gateway configuration file is JSON (often saved with `.conf` by convention).

* parser/loader: `../p4p/src/p4p/gw.py` (JSON + C-style comments)
* docs: `../p4p/documentation/gw.rst`

Notable behavior:

* keys beginning with `EPICS_PVA_` are passed through and interpreted like the environment variables, but scoped to a particular gateway client/server instance.

YAML constraints to capture:

* YAML should map 1:1 with the existing JSON schema and semantics.

### IOC group definition files (pvxs)

In `../pvxs` QSRV group definitions are JSON.

* docs: `../pvxs/documentation/qgroup.rst`
* loader: `dbLoadGroup()` (pvxs IOC integration)

YAML constraints to capture:

* YAML should map 1:1 with the existing JSON schema and semantics.

### New: PVA client/server configuration file (environment replacement)

Goal: have a file (eg. `pva.yaml`) which can contain the knobs that are currently configured via environment variables.

Preferred (more YAML-like) shape:

```yaml
version: 1

client:
  epics:
    addr_list:
      names:
        - "..."
      auto: true
    name_servers:
      names:
        - "..."
    tls:
      keychain: "/home/me/.config/pva/1.5/client.p12"

server:
  epics:
    addr_list:
      names:
        - "..."
      auto: true
    tls:
      keychain: "/home/me/.config/pva/1.5/server.p12"
```

Mapping notes:

* The nested form is *canonical*.
* Loaders normalize nested keys into the corresponding `EPICS_PVA_*` / `EPICS_PVAS_*` settings internally.
  Example mappings (illustrative, not exhaustive):
  * `client.epics.addr_list.names` → `EPICS_PVA_ADDR_LIST`
  * `client.epics.addr_list.auto` → `EPICS_PVA_AUTO_ADDR_LIST`
  * `client.epics.name_servers.names` → `EPICS_PVA_NAME_SERVERS`
  * `client.epics.tls.keychain` → `EPICS_PVA_TLS_KEYCHAIN`
  * `server.epics.tls.keychain` → `EPICS_PVAS_TLS_KEYCHAIN`

Compatibility option (for passthrough users/tools):

* Optionally accept a raw environment-variable map, but treat it as a compatibility layer, not the primary schema.
  eg.

```yaml
client:
  env:
    EPICS_PVA_ADDR_LIST: "..."
```

This keeps the schema human-friendly while still allowing integration with systems which already speak in `EPICS_PVA_*` keys (eg. p4p gateway JSON).

## Naming conventions for YAML variants

Recommendation: preserve the historical type information by using a **double-extension**, with YAML last.

Examples:

* `something.db.yaml` / `something.db.yml`
* `something.dbd.yaml`
* `something.acf.yaml`
* `something.substitutions.yaml`
* `something.template.yaml` (if YAML is introduced for templates specifically)
* `something.qgroup.yaml` (pvxs group definitions)
* `something.pvagw.yaml` (p4p gateway config)

Rationale:

* Humans can still infer the legacy “type” immediately.
* Editors, formatters, and linters key off the final `.yaml`/`.yml`.

## Default locations and default names (XDG-style)

There is existing precedent (eg. pvxs docs/code) using:

* `${XDG_CONFIG_HOME}/pva/1.5/` (often `~/.config/pva/1.5/`)
* `${XDG_DATA_HOME}/pva/1.5/` (often `~/.local/share/pva/1.5/`)

Proposed defaults for new env-replacement config:

* client: `${XDG_CONFIG_HOME}/pva/1.5/client.yaml`
* server: `${XDG_CONFIG_HOME}/pva/1.5/server.yaml`

These do not collide with existing `client.p12` / `server.p12` keychains.

## Proposed architecture: one reusable YAML frontend + format-specific builders

Design requirement: “a common parser is used everywhere that can be configured to call out to build up the desired output”.

### Key idea

Implement a single YAML frontend which produces a *common intermediate representation* (IR) and/or a common event stream.
Then attach format-specific builders/emitters which translate that IR into the in-memory structures needed by each subsystem.

This yields:

* one YAML reader, one error reporting strategy, one include/anchor policy,
* multiple “backends” (db/dbd/acf/substitutions/pva config/…) without duplicating YAML parsing.

### File type identification (dispatch)

Dispatch order (highest precedence first):

1. Explicit user/API parameter (eg. `dbLoadRecordsYaml()` knows it is DB)
2. YAML header marker (optional): first document comment `# EPICS YAML`
3. A required top-level key naming the kind, eg. `kind: epics.db` (recommended)
4. Double-extension inference (`*.db.yaml`, `*.acf.yaml`, …)

Recommendation: require `kind:` for new YAML-only formats (like `pva.yaml`), allow it to be optional for double-extension legacy mirrors.

### Common YAML IR (minimum viable)

Define a small generic tree representation with:

* scalars (string/int/float/bool/null)
* sequences
* mappings (ordered)
* source location spans (file, line, column)

This IR should *not* bake in any EPICS specifics. EPICS specifics live in the backend builders.

### Common parse context

The YAML frontend should be configured with a context object:

* search/include path list
* “base directory” of the root file
* macro dictionary (optional)
* strictness knobs (unknown keys, type coercions)
* error/warning callbacks

### Backend interface (builder)

Define a registry of “builders” keyed by `kind`.

Pseudocode:

```c
typedef struct epicsYamlNode epicsYamlNode;

typedef struct {
    const char* filename;
    const char* kind;     /* eg. "epics.acf", "epics.db", "epics.dbd" */
    const char* version;  /* schema/version string from YAML */
    void* user;           /* backend-specific context */
} epicsYamlContext;

typedef struct {
    const char* kind;
    /* Validate the YAML tree and build the backend output.
     * Return 0 on success, non-zero on error.
     */
    int (*build)(epicsYamlContext* ctx, const epicsYamlNode* root);
} epicsYamlBuilder;

int epicsYamlRegister(const epicsYamlBuilder* builder);
int epicsYamlLoadFile(epicsYamlContext* ctx, const char* filename);
```

Each subsystem provides a builder which:

* validates expected keys/types,
* applies defaults,
* constructs native in-memory objects
  * OR emits legacy text and then calls the existing legacy parser (as a transitional implementation strategy).

### Transitional strategy: YAML → legacy text → existing parser

For formats already backed by lex/yacc (DB/DBD/ACF/substitutions), the fastest path is often:

1. YAML frontend parses YAML into IR.
2. Format builder renders *canonical legacy text* (deterministic ordering).
3. Existing legacy parser is invoked on that rendered text.

This still satisfies “one YAML parser everywhere”, while avoiding duplicating the semantic parsers initially.
If/when needed, individual builders can be upgraded to build native structures directly.

### Schema/versioning conventions

Recommended top-level fields for all EPICS YAML documents:

* `# EPICS YAML` (comment marker)
* `version: 1.0` (document schema version)
* `kind: epics.<format>`
* optional `$schema:` for editor tooling (JSON Schema URL)

Example:

```yaml
# EPICS YAML
version: 1.0
kind: epics.acf
$schema: https://…/epics-access-security-schema.json
...
```

### Dependency and security note (NO external YAML library)

The YAML frontend **must be implemented directly in C++ inside epics-base**.

Rationale:

* epics-base targets a wide variety of platforms/architectures where integrating third-party YAML libraries is costly.
* security review and long-term maintenance are simplified when the accepted YAML grammar is intentionally small and fully owned.

Implication:

* We implement and support a **restricted YAML subset** suitable for configuration and data description.
* Anything outside this subset must fail with a clear diagnostic.

---

# Implementation Plan (epics-base)

This section is an implementable feature plan for epics-base.

## Assumptions

1. **YAML file identification**
   * Primary: explicit `kind:` at top level for YAML-only formats.
   * For “YAML mirrors” of legacy formats, prefer double-extension inference (`*.db.yaml`, `*.acf.yaml`, …). `kind:` is allowed and overrides inference.

2. **Versioning**
   * All EPICS YAML documents include `version: 1` (integer).
   * Backends may also define a backend-specific `schema:` or `$schema:` for editor tooling.

3. **YAML grammar subset** (to keep implementation predictable and safe)
   * Support a single YAML document per file (optional `---` document start accepted; no multi-document streams).
   * Only JSON-compatible nodes: scalars, sequences, mappings.
   * Scalars:
     * strings: plain, single-quoted, double-quoted
     * booleans: `true|false`
     * null: `null|~`
     * numbers: decimal integers and floats (no sexagesimal, no infinities)
   * Indentation:
     * spaces only (no tabs)
     * consistent indentation required; treat indentation errors as hard errors
   * Comments: `# ...` to end-of-line.
   * Explicitly **NOT supported** (initially): anchors/aliases, merge keys, tags, complex keys, block scalars (`|`/`>`), flow-style collections (`{}`/`[]`), and implicit typing beyond the scalar set above.
   * Parser hard-limits (security): max file size, max nesting depth, max total nodes, and max line length.

4. **Strategy**
   * **Phase 1** uses *YAML → canonical legacy text → existing parser* for DB/DBD/ACF/substitutions.
   * **Phase 2+** (optional) converts selected formats to build native structures directly.

## Feature set overview

The work is organized into a common YAML frontend plus per-format backends.

### Common, reusable YAML frontend (shared by everything)

**F0. Add `epicsYaml` library (new code in epics-base)**

Deliverables:

* A single YAML loader API, built once and used everywhere.
* A builder registry keyed by `kind`.
* A small IR with source locations for diagnostics.

Implementation notes:

* Implement this in `modules/libcom` (or another low-level module) so both IOC code and host tools can reuse it.
* Implement the YAML parser directly in C++ (no external YAML library) for the restricted subset described above.
* Provide two interfaces:
  1) DOM/IR builder (`epicsYamlLoadTree()`), and
  2) “build directly” convenience (`epicsYamlLoadFile(ctx, filename)` + `kind` dispatch).

**F1. File type detection / dispatch (centralized)**

Rules:

1. If the caller explicitly selects a backend (eg. DB vs ACF), dispatch directly.
2. Else determine `kind`:
   * if top-level `kind:` exists, use it,
   * else infer from filename double-extension:
     * `*.db.yaml` → `epics.db`
     * `*.dbd.yaml` → `epics.dbd`
     * `*.acf.yaml` → `epics.acf`
     * `*.substitutions.yaml` → `epics.substitutions`
     * `client.yaml`/`server.yaml` in the PVA config directory → `epics.pva.client` / `epics.pva.server` (or require `kind:`)
3. If `kind` cannot be determined, error with a diagnostic that suggests adding `kind:`.

**F2. Canonical error reporting**

* All YAML parse errors and backend schema errors include filename:line:column.
* Backends return structured diagnostics (severity, message, node span).

**F3. Includes and search paths (uniform policy)**

* Common parse context includes:
  * base directory
  * include/search path list
  * macro dictionary (for formats which need it)
* YAML backends may implement `include:` keys, but include semantics must be consistent across all EPICS YAML formats.
  Suggested policy:
  * `include:` accepts either a string or list of strings.
  * relative paths are resolved relative to the including file.
  * include cycles are detected.

### Format backends (epics-base)

Each backend:

* validates a YAML schema (informal at first; JSON Schema can follow)
* applies defaults
* either:
  * renders canonical legacy text and calls the existing parser, or
  * builds native structures directly

#### A) Access Security (ACF) backend

**F4. Implement `epics.acf` backend**

Canonical YAML shape (aligned with the existing pvxs examples):

```yaml
version: 1
kind: epics.acf
authorities: []   # optional
uags: []          # optional
hags: []          # optional
asgs:
  - name: DEFAULT
    rules:
      - level: 0
        access: NONE|READ|WRITE|RPC
        trapwrite: false
        uags: []          # optional
        hags: []          # optional
        methods: []       # optional
        authorities: []   # optional
        calc: "VAL>=0"   # optional
```

Implementation approach:

* Render legacy `.acf` text deterministically and feed it through the existing ACF parser (asLib).
* Keep a strict mapping for features present in legacy grammar; error on unknown keys.

Entry points:

* Update `asInit()` loading path so that if the configured filename ends with `.yaml`/`.yml` it loads via the YAML backend.
* (Optional) add `asSetFilenameYaml()` iocsh helper, but extension-based detection is sufficient.

#### B) DB/DBD backend

**F5. Implement `epics.db` and `epics.dbd` backends**

Canonical YAML shape (assumed):

```yaml
version: 1
kind: epics.db
records:
  - type: ai
    name: "REC:NAME"
    fields:
      VAL: "0"
      DESC: "Example"
    info:
      "Q:group": '{"grp:name": {"X": {"+channel": "REC:NAME.VAL"}}}'
```

And for DBD:

```yaml
version: 1
kind: epics.dbd
include:
  - "base.dbd"
registrars:
  - "myregistrar"
```

Implementation approach:

* Render canonical legacy `.db`/`.dbd` text and call `dbReadDatabase()`.
  * For `.dbd.yaml`, the renderer emits DBD constructs.
  * For `.db.yaml`, the renderer emits DB record instances.

Entry points:

* Extend `dbReadDatabase()` to accept YAML via filename extension and/or `kind`.
  * If the caller uses `dbLoadRecords("foo.db.yaml", ...)`, `dbReadDatabase()` will dispatch to the YAML backend.
  * This ensures both IOC and host tools which call `dbReadDatabase()` gain YAML support.

#### C) Substitutions / dbLoadTemplate backend

**F6. Implement `epics.substitutions` backend**

Canonical YAML shape (assumed):

```yaml
version: 1
kind: epics.substitutions
templates:
  - file: "db/my.template"   # DB syntax template
    substitutions:
      - P: "DEV:"
        R: "A"
      - P: "DEV:"
        R: "B"
```

Implementation approach:

* Render canonical legacy `.substitutions` text and call the existing `dbLoadTemplate()` path.

Entry points:

* Extend `dbLoadTemplate()` so that `.substitutions.yaml` is accepted (detected by extension and/or `kind`).
* Keep `msi` unchanged initially; later it can be extended to accept YAML substitutions using the same backend.

#### D) PVA config backend (new YAML-only format)

**F7. Implement `epics.pva.client` / `epics.pva.server` backends**

Canonical nested YAML shape (as requested):

```yaml
version: 1
kind: epics.pva.client
epics:
  addr_list:
    names:
      - "1.2.3.4"
      - "10.0.0.0/24"
    auto: true
  name_servers:
    names:
      - "ioc:5075"
  tls:
    keychain: "~/.config/pva/1.5/client.p12"
```

Behavior:

* Loader normalizes to the effective internal settings (equivalent to `EPICS_PVA_*` / `EPICS_PVAS_*`).
* Provide an optional compatibility `env:` map which is merged last:

```yaml
env:
  EPICS_PVA_ADDR_LIST: "..."
```

Integration points (epics-base scope):

* Provide a small API that produces an in-memory “settings map” (string→string) and can optionally apply it to the process environment or a library-specific configuration object.
* Provide a default search order:
  1) explicit filename via new API
  2) `${XDG_CONFIG_HOME}/pva/1.5/client.yaml` or `server.yaml`
  3) environment variables (existing behavior) as fallback

### Testing and verification

**F8. Unit tests for YAML frontend**

* parse errors include correct filename/line/column
* include cycle detection
* strict schema validation errors

**F9. Golden tests per backend**

For each legacy format, provide:

* a legacy input file
* an equivalent YAML input file
* a golden “canonical legacy text” output produced by the YAML renderer

Then ensure:

* legacy parse result == YAML parse result (semantic equivalence)

### Documentation and migration

**F10. Document schemas and migration guidance**

* Add example YAML files for each format.
* Recommend double-extension naming.
* Define precedence between legacy and YAML files (explicit filename wins).

---

# Parallelization plan

These can be implemented in parallel once the YAML frontend (F0–F3) is in place:

* ACF backend (F4)
* DB/DBD backend (F5)
* Substitutions backend (F6)
* PVA config backend (F7)
* Tests (F8–F9)

Recommended serial dependency:

1) F0–F3
2) F4/F5/F6/F7 in parallel
3) F8–F10

---

# Follow-on work (NOT in epics-base; handoff to other project)

This repo should only provide the reusable YAML frontend and the EPICS Base format backends.

## pvxs

* Group definitions: today JSON schema + `dbLoadGroup()`.
  * Add a YAML loader which maps YAML 1:1 to the existing JSON schema.
  * Recommended naming: `*.qgroup.yaml` (or `kind: pvxs.qgroup`).
* ACF YAML: pvxs already has examples and some YAML generation, but a full YAML ACF parser should reuse the same schema as `epics.acf` (or vendor it), not implement a second dialect.
* PVA config: if pvxs reads environment variables today, add a loader for `${XDG_CONFIG_HOME}/pva/1.5/{client,server}.yaml` which produces the same effective configuration.

## p4p gateway

* Gateway config is JSON today (`gw.py`).
* Add YAML support by accepting YAML as an alternative serialization of the same schema (YAML→Python dict), preserving the existing semantics including `EPICS_PVA_*` pass-through keys.
