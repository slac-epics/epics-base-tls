/*************************************************************************\
* Copyright (c) 2018 Michael Davidsaver
* SPDX-License-Identifier: EPICS
* EPICS BASE is distributed subject to a Software License Agreement found
* in file LICENSE that is included with this distribution.
\*************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <testMain.h>
#include <epicsUnitTest.h>

#include <errSymTbl.h>
#include <epicsString.h>
#include <osiFileName.h>
#include <errlog.h>

#include <asLib.h>

// For tests these are the values of the client that are being tested against the given Access Security Group
static char *asUser,
            *asHost,
            *asMethod,
            *asAuthority;
static enum AsProtocol protocol=AS_PROTOCOL_TCP;
static int asAsl;

/**
 * @brief Test data with Host Access Groups (HAG)
 *
 * This includes a host access group (HAG) for localhost and a default Access Security Group (ASG)
 * with rules for read and write access to the HAG.
 */
static const char hostname_config[] = ""
    "HAG(foo) {localhost}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n"

    "ASG(rw) {\n"
    "    RULE(1, WRITE) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * @brief Test data with METHOD, AUTHORITY, and PROTOCOL Access Security Group configurations
 *
 * This is a test case for `METHOD`, `AUTHORITY`, and `PROTOCOL` Access Security Group configurations
 * It includes a Access Security Group (ASG) that is configured to allow access
 * to PV resources controlled by `METHOD` and `AUTHORITY` constraints.
 * It also showcases the use of `PROTOCOL` to specify constraints based on the transport layer security used.
 * It also includes an example of the `RPC` permission type for the `rwx` rule.
 */
static const char method_auth_config[] = ""
    "UAG(bar) {boss}\n"
    "UAG(foo) {testing}\n"
    "UAG(ops) {geek}\n"

    "ASG(DEFAULT) {\n"
    "\tRULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "\tRULE(0, NONE)\n"
    "\tRULE(1, READ) {\n"
    "\t\tUAG(foo,ops)\n"
    "\t\tMETHOD(\"ca\")\n"
    "\t\tPROTOCOL(\"TCP\")\n"
    "\t}\n"
    "}\n"

    "ASG(rw) {\n"
    "\tRULE(0, NONE)\n"
    "\tRULE(1, WRITE, TRAPWRITE) {\n"
    "\t\tUAG(foo)\n"
    "\t\tMETHOD(\"x509\")\n"
    "\t\tAUTHORITY(\"Epics Org CA\")\n"
    "\t}\n"
    "}\n"

    "ASG(rwx) {\n"
    "\tRULE(0, NONE)\n"
    "\tRULE(1, RPC) {\n"
    "\t\tUAG(bar)\n"
    "\t\tMETHOD(\"x509\",\"ignored\",\"ignored_too\")\n"
    "\t\tAUTHORITY(\"Epics Org CA\",\"ignored\",\"ORNL Org CA\")\n"
    "\t\tPROTOCOL(\"TLS\")\n"
    "\t}\n"
    "}\n";

/**
 * Defines the expected output of asDumpFP() for the `method_auth_config` test case.
 *
 * This should be a direct copy of the `method_auth_config` string except that
 * all spaces in string lists are removed, and the default RULE flag (`NOTRAPWRITE`) is
 * added when it is not present in the original string.
 */
static const char *expected_method_auth_config =
    "UAG(bar) {boss}\n"
    "UAG(foo) {testing}\n"
    "UAG(ops) {geek}\n"

    "ASG(DEFAULT) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "}\n"

    "ASG(ro) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "\tRULE(1,READ,NOTRAPWRITE) {\n"
    "\t\tUAG(foo,ops)\n"
    "\t\tMETHOD(\"ca\")\n"
    "\t\tPROTOCOL(\"tcp\")\n"
    "\t}\n"
    "}\n"

    "ASG(rw) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "\tRULE(1,WRITE,TRAPWRITE) {\n"
    "\t\tUAG(foo)\n"
    "\t\tMETHOD(\"x509\")\n"
    "\t\tAUTHORITY(\"Epics Org CA\")\n"
    "\t}\n"
    "}\n"

    "ASG(rwx) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "\tRULE(1,RPC,NOTRAPWRITE) {\n"
    "\t\tUAG(bar)\n"
    "\t\tMETHOD(\"x509\",\"ignored\",\"ignored_too\")\n"
    "\t\tAUTHORITY(\"Epics Org CA\",\"ignored\",\"ORNL Org CA\")\n"
    "\t\tPROTOCOL(\"tls\")\n"
    "\t}\n"
    "}\n";

/**
 * Defines the expected output of asDumpRulesFP() for the `DEFAULT` Access Security Group.
 *
 * This should be a direct copy of the `method_auth_config` DEFAULT ASG string except that
 * all spaces in string lists are removed, and the default RULE flag (`NOTRAPWRITE`) is
 * added when it is not present in the original string.
 */
static const char *expected_DEFAULT_rules_config =
    "ASG(DEFAULT) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "}\n";

/**
 * Defines the expected output of asDumpRulesFP() for the `ro` Access Security Group.
 *
 * This should be a direct copy of the `method_auth_config` ro ASG string except that
 * all spaces in string lists are removed, and the default RULE flag (`NOTRAPWRITE`) is
 * added when it is not present in the original string.
 */
static const char *expected_ro_rules_config =
    "ASG(ro) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "\tRULE(1,READ,NOTRAPWRITE) {\n"
    "\t\tUAG(foo,ops)\n"
    "\t\tMETHOD(\"ca\")\n"
    "\t\tPROTOCOL(\"tcp\")\n"
    "\t}\n"
    "}\n";

/**
 * Defines the expected output of asDumpRulesFP() for the `rw` Access Security Group.
 *
 * This should be a direct copy of the `method_auth_config` rw ASG string except that
 * all spaces in string lists are removed, and the default RULE flag (`NOTRAPWRITE`) is
 * added when it is not present in the original string.
 */
static const char *expected_rw_rules_config =
    "ASG(rw) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "\tRULE(1,WRITE,TRAPWRITE) {\n"
    "\t\tUAG(foo)\n"
    "\t\tMETHOD(\"x509\")\n"
    "\t\tAUTHORITY(\"Epics Org CA\")\n"
    "\t}\n"
    "}\n";

/**
 * Defines the expected output of asDumpRulesFP() for the `rwx` Access Security Group.
 *
 * This should be a direct copy of the `method_auth_config` rwx ASG string except that
 * all spaces in string lists are removed, and the default RULE flag (`NOTRAPWRITE`) is
 * added when it is not present in the original string.
 */
static const char *expected_rwx_rules_config =
    "ASG(rwx) {\n"
    "\tRULE(0,NONE,NOTRAPWRITE)\n"
    "\tRULE(1,RPC,NOTRAPWRITE) {\n"
    "\t\tUAG(bar)\n"
    "\t\tMETHOD(\"x509\",\"ignored\",\"ignored_too\")\n"
    "\t\tAUTHORITY(\"Epics Org CA\",\"ignored\",\"ORNL Org CA\")\n"
    "\t\tPROTOCOL(\"tls\")\n"
    "\t}\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should be silently ignored, but the rest of the config is processed.
 *
 * top-unknown-keyword(WELL,FORMED,LIST)
 * - valid top level keyword with well-formed arg list
 */
static const char supported_config_1[] = ""
    "HAG(foo) {localhost}\n"

    "GENERIC(WELL, FORMED, ARG, LIST)\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should be silently ignored, but the rest of the config is processed.
 *
 * top-unknown-keyword(WELL,FORMED,LIST) { WELL,FORMED,LIST }
 * - valid top level keyword with well-formed arg list and valid arg list body
 */
static const char supported_config_2[] = ""
    "HAG(foo) {localhost}\n"

    "SIMPLE(WELL, FORMED, ARG, LIST) {\n"
    "    WELL, FORMED, LIST\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should be silently ignored, but the rest of the config is processed.
 *
 * top-unknown-keyword(WELL,FORMED,LIST) { recursive-body-keyword(WELL,FORMED,LIST) }
 * - valid top level keyword with well-formed arg list and valid recursive body
 * - includes quoted strings, integers, and floating point numbers
 */
static const char supported_config_3[] = ""
    "HAG(foo) {localhost}\n"

    "COMPLEX_ARGUMENTS(1, WELL, \"FORMED\", ARG, LIST) {\n"
    "    ALSO_GENERIC(WELL, FORMED, ARG, LIST, 2.0) \n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should be silently ignored, but the rest of the config is processed.
 *
 * top-unknown-keyword(WELL,FORMED,LIST) { recursive-body-keyword(WELL,FORMED,LIST) { AND_BODY } }
 * - valid top level keyword with well-formed arg list and valid recursive body, with a nested body
 * - includes floating point numbers, and an empty arg list
 */
static const char supported_config_4[] = ""
"HAG(foo) {localhost}\n"

"SUB_BLOCKS(1.0, ARGS) {\n"
"    ALSO_GENERIC() {\n"
"        AND_LIST_BODY\n"
"    }\n"
"    ANOTHER_GENERIC() {\n"
"        BIGGER, LIST, BODY\n"
"    }\n"
"}\n"

"ASG(DEFAULT) {\n"
"    RULE(0, NONE)\n"
"}\n"

"ASG(ro) {\n"
"    RULE(0, NONE)\n"
"    RULE(1, READ) {\n"
"        HAG(foo)\n"
"    }\n"
"}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should be silently ignored, but the rest of the config is processed.
 *
 * top-unknown-keyword(WELL,FORMED,LIST) { recursive-body-keyword(WELL,FORMED,LIST) { AND_RECURSIVE_BODY() {LIST, LIST } }
 * - valid top level keyword with well-formed arg list and valid recursive body, with a nested recursion
 * - includes floating point numbers, and an empty arg list
 */
static const char supported_config_5[] = ""
    "HAG(foo) {localhost}\n"

    "RECURSIVE_SUB_BLOCKS(1.0, -2.3, +4.5, ARGS, +2.71828E-23, -2.71828e+23, +12, -13, +-14) {\n"
    "    ALSO_GENERIC() {\n"
    "        AND_RECURSIVE(FOO) {\n"
    "            LIST, BODY\n"
    "        }\n"
    "    }\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(+1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should be silently ignored, but the rest of the config is processed.
 *
 * top-unknown-keyword(KEYWORD) { KEYWORD(KEYWORD) }
 * - valid top level keyword with keyword for args, recursive body name, and arg list
 * - top level generic items referenced in RULES, then RULES are ignored
 */
static const char supported_config_6[] = ""
    "HAG(foo) {localhost}\n"

    "WITH_KEYWORDS(UAG) {\n"
    "    ASG(HAL, IMP, CALC, RULE)\n"
    "    HAL(USG, METHOD) {\n"
    "        PROTOCOL(\"TLS\", AUTHORITY)\n"
    "    }\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ignored) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        WITH_KEYWORDS(UAG)\n"
    "    }\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "    RULE(2, WRITE) {\n"
    "        WITH_KEYWORDS(UAG)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported elements should be silently ignored, and the rule will not match,
 * but the rest of the config is processed.
 *
 * - RULE contains unsupported elements
 */
static const char supported_config_7[] = ""
    "HAG(foo) {localhost}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "        BAD_PREDICATE(\"x509\")\n"
    "        BAD_PREDICATE_AS_WELL(\"EPICS Certificate Authority\")\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported elements should be silently ignored, and the rule will not match,
 * but the rest of the config is processed.
 *
 * - unexpected permission name in arg list for RULE element ignored
 */
static const char supported_config_8[] = ""
        "HAG(foo) {localhost}\n"

        "ASG(DEFAULT) {\n"
        "    RULE(0, NONE)\n"
        "}\n"

        "ASG(ro) {\n"
        "    RULE(0, NONE)\n"
        "    RULE(1, ADDITIONAL_PERMISSION) {\n"
        "        HAG(foo)\n"
        "    }\n"
        "}\n"
        ;

/**
 * Test data with unsupported elements.
 * The unsupported elements should be silently ignored, and the rule will not match,
 * but the rest of the config is processed.
 *
 * - RULE containing unexpected protocol name ignored
 */
static const char supported_config_9[] = ""
        "HAG(foo) {localhost}\n"

        "ASG(DEFAULT) {\n"
        "\tRULE(0, NONE)\n"
        "}\n"

        "ASG(ro) {\n"
        "\tRULE(0, NONE)\n"
        "\tRULE(1, WRITE) {\n"
        "\t\tHAG(foo)\n"
        "\t\tPROTOCOL(UNKNOWN_PROTOCOL)\n"
        "\t}\n"
        "}\n"
        ;

/**
 * Test data with unsupported elements.
 * The unsupported element should cause an error as the format is invalid.
 *
 * top-unknown-keyword( a b )
 * - invalid arg list missing commas
 */
static const char unsupported_config_1[] = ""
    "HAG(foo) {localhost}\n"

    "GENERIC(not well-formed arg list)\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should cause an error as the format is invalid.
 *
 * top-unknown-keyword(WELL,FORMED,LIST) { a b }
 * - invalid string list
 */
static const char unsupported_config_2[] = ""
    "HAG(foo) {localhost}\n"

    "GENERIC(WELL, FORMED, ARG, LIST) {\n"
    "    NOT WELL-FORMED BODY\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should cause an error as the format is invalid.
 *
 * top-unknown-keyword { a, b }
 * - missing parameters (must have at least an empty arg list)
 */
static const char unsupported_config_3[] = ""
    "HAG(foo) {localhost}\n"

    "GENERIC {\n"
    "    WELL, FORMED, LIST, BODY\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should cause an error as the format is invalid.
 *
 * top-unknown-keyword(WELL,FORMED,LIST) { X, Y(a b c) }
 * - bad arg list for recursive body
 */
static const char unsupported_config_4[] = ""
    "HAG(foo) {localhost}\n"

    "GENERIC(WELL, FORMED, ARG, LIST) {\n"
    "    BODY(BAD ARG LIST)\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Test data with unsupported elements.
 * The unsupported element should cause an error as the format is invalid.
 *
 * top-unknown-keyword(WELL,FORMED,LIST) { X, Y(a b c) }
 * - mix of list and recursive type bodies
 */
static const char unsupported_config_5[] = ""
    "HAG(foo) {localhost}\n"

    "GENERIC(WELL, FORMED, ARG, LIST) {\n"
    "    LIST, BODY, MIXED, WITH,\n"
    "    RECURSIVE_BODY(ARG, LIST)\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * The modification to a well known element should cause an error.
 *
 * - bad arg list for ASG element
 */
static const char unsupported_mod_1[] = ""
    "HAG(foo) {localhost}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro BAD ARG LIST) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * The modification to a well known element should cause an error.
 *
 * - bad arg list for HAG element
 */
static const char unsupported_mod_2[] = ""
    "HAG(BAD ARG LIST) {localhost}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * The modification to a well known element should cause an error.
 *
 * - bad arg list for RULE element
 */
static const char unsupported_mod_3[] = ""
    "HAG(foo) {localhost}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0 BAD ARG LIST)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * The modification to a well known element should cause an error.
 *
 * - bad arg count for ASG element
 */
static const char unsupported_mod_4[] = ""
    "HAG(foo) {localhost}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro, UNKNOWN_PERMISSION) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * The modification to a well known element should cause an error.
 *
 * - unexpected name in arg list for RULE element
 */
static const char unsupported_mod_5[] = ""
    "HAG(foo) {localhost}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE, UNKNOWN_FLAG)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * The modification to a well known element should cause an error.
 *
 * - unexpected recursive body mixed in with HAG string list body
 */
static const char unsupported_mod_6[] = ""
    "HAG(foo) {\n"
    "    localhost,\n"
    "    NETWORK(\"127.0.0.1\")\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * The modification to a well known element should cause an error.
 *
 * - unexpected recursive body mixed in with UAG string list body
 */
static const char unsupported_mod_7[] = ""
    "UAG(foo) {\n"
    "    alice,\n"
    "    GROUP(admin)\n"
    "}\n"

    "ASG(DEFAULT) {\n"
    "    RULE(0, NONE)\n"
    "}\n"

    "ASG(ro) {\n"
    "    RULE(0, NONE)\n"
    "    RULE(1, READ) {\n"
    "        HAG(foo)\n"
    "    }\n"
    "}\n";

/**
 * Set the username for the authorization tests
 */
static void setUser(const char *name)
{
    free(asUser);
    asUser = epicsStrDup(name);
}

/**
 * Set the hostname for the authorization tests
 */
static void setHost(const char *name)
{
    free(asHost);
    asHost = epicsStrDup(name);
}

static void setMethod(const char *name)
{
    free(asMethod);
    asMethod = epicsStrDup(name);
}

static void setAuthority(const char *name)
{
    free(asAuthority);
    asAuthority = epicsStrDup(name);
}

static void setProtocol(enum AsProtocol the_protocol)
{
    protocol = the_protocol;
}

/**
 * Test the access control system with the given ASG, user, and hostname
 * This will test that the expected access given by mask is granted
 * when the Access Security Group (ASG) is interpreted in the
 * context of the configured user, host, and Level (asl).
 */
static void testAccess(const char *asg, unsigned mask)
{
    ASMEMBERPVT asp = 0; /* aka dbCommon::asp */
    ASCLIENTPVT client = 0;
    long ret;

    ret = asAddMember(&asp, asg);
    if(ret) {
        testFail("testAccess(ASG:%s, USER:%s, METHOD:%s, AUTHORITY:%s, HOST:%s, PROTOCOL:%s, ASL:%d) -> asAddMember error: %s",
                 asg, asUser, asMethod?asMethod:"", asAuthority?asAuthority:"", asHost, protocol ? "true":"false", asAsl, errSymMsg(ret));
    } else {
        ret = asAddClientIdentity(&client, asp, asAsl, (ASIDENTITY){ .user = asUser, .host = asHost, .method = asMethod, .authority = asAuthority, .protocol = protocol });
    }
    if(ret) {
        testFail("testAccess(ASG:%s, USER:%s, METHOD:%s, AUTHORITY:%s, HOST:%s, PROTOCOL:%s, ASL:%d) -> asAddClient error: %s",
                 asg, asUser, asMethod?asMethod:"", asAuthority?asAuthority:"", asHost, protocol ? "true":"false", asAsl, errSymMsg(ret));
    } else {
        unsigned actual = 0;
        actual |= asCheckGet(client) ? 1 : 0;
        actual |= asCheckPut(client) ? 2 : 0;
        actual |= asCheckRPC(client) ? 4 : 0;
        testOk(actual==mask, "testAccess(ASG:%s, USER:%s, METHOD:%s, AUTHORITY:%s, HOST:%s, PROTOCOL:%s, ASL:%d) -> %x == %x",
               asg, asUser, asMethod?asMethod:"", asAuthority?asAuthority:"", asHost, protocol ? "true":"false", asAsl, actual, mask);
    }
    if(client) asRemoveClient(&client);
    if(asp) asRemoveMember(&asp);
}

static void testSyntaxErrors(void)
{
    static const char empty[] = "\n#almost empty file\n\n";
    static const char duplicateMethod[] = "\nASG(foo) {RULE(0, NONE) {METHOD   (\"x509\"        )  METHOD   (\"x509\"        )}}\n\n";
    static const char duplicateAuthority[] = "\nASG(foo) {RULE(0, NONE) {AUTHORITY(\"Epics Org CA\")  AUTHORITY(\"Epics Org CA\")}}\n\n";
    static const char notDuplicateMethod[] = "\nASG(foo) {RULE(0, NONE) {METHOD   (\"x509\"        )} RULE(1, RPC            ) {METHOD   (\"x509\"        )}}\n\n";
    static const char notDuplicateAuthority[] = "\nASG(foo) {RULE(0, NONE) {AUTHORITY(\"Epics Org CA\")} RULE(1, WRITE,TRAPWRITE) {AUTHORITY(\"Epics Org CA\")}}\n\n";
    static const char anotherNotDuplicatedMethod[] = "\nASG(foo) {RULE(0, NONE) {METHOD   (\"x509\"        )  METHOD   (\"ca\"          )}}\n\n";
    static const char anotherNotDuplicatedAuthority[] = "\nASG(foo) {RULE(0, NONE) {AUTHORITY(\"Epics Org CA\")  AUTHORITY(\"ORNL CA\"     )}}\n\n";
    long ret;

    testDiag("testSyntaxErrors()");
    asCheckClientIP = 0;

    eltc(0);
    ret = asInitMem(empty, NULL);
    testOk(ret==S_asLib_badConfig, "load \"empty\" config -> %s", errSymMsg(ret));

    ret = asInitMem(duplicateMethod, NULL);
    testOk(ret==S_asLib_badConfig, "load \"duplicate method rule\" config -> %s", errSymMsg(ret));

    ret = asInitMem(duplicateAuthority, NULL);
    testOk(ret==S_asLib_badConfig, "load \"duplicate authority rule\" config -> %s", errSymMsg(ret));

    ret = asInitMem(notDuplicateMethod, NULL);
    testOk(ret==0, "load non \"duplicate method rule\" config -> %s", errSymMsg(ret));

    ret = asInitMem(notDuplicateAuthority, NULL);
    testOk(ret==0, "load non \"duplicate authority rule\" config -> %s", errSymMsg(ret));

    ret = asInitMem(anotherNotDuplicatedMethod, NULL);
    testOk(ret==0, "load another non \"duplicate method rule\" config -> %s", errSymMsg(ret));

    ret = asInitMem(anotherNotDuplicatedAuthority, NULL);
    testOk(ret==0, "load another non \"duplicate authority rule\" config -> %s", errSymMsg(ret));

    eltc(1);
}

static void testHostNames(void)
{
    testDiag("testHostNames()");
    asCheckClientIP = 0;

    testOk1(asInitMem(hostname_config, NULL)==0);

    setUser("testing");
    setHost("localhost");
    asAsl = 0;

    testAccess("invalid", 0);
    testAccess("DEFAULT", 0);
    testAccess("ro", 1);
    testAccess("rw", 3);

    setHost("127.0.0.1");

    testAccess("invalid", 0);
    testAccess("DEFAULT", 0);
    testAccess("ro", 0);
    testAccess("rw", 0);

    setHost("guaranteed.invalid.");

    testAccess("invalid", 0);
    testAccess("DEFAULT", 0);
    testAccess("ro", 0);
    testAccess("rw", 0);
}

static void testUseIP(void)
{
    testDiag("testUseIP()");
    asCheckClientIP = 1;

    /* still host names in .acf */
    testOk1(asInitMem(hostname_config, NULL)==0);
    /* now resolved to IPs */

    setUser("testing");
    setHost("localhost"); /* will not match against resolved IP */
    asAsl = 0;

    testAccess("invalid", 0);
    testAccess("DEFAULT", 0);
    testAccess("ro", 0);
    testAccess("rw", 0);

    setHost("127.0.0.1");

    testAccess("invalid", 0);
    testAccess("DEFAULT", 0);
    testAccess("ro", 1);
    testAccess("rw", 3);

    setHost("guaranteed.invalid.");

    testAccess("invalid", 0);
    testAccess("DEFAULT", 0);
    testAccess("ro", 0);
    testAccess("rw", 0);
}

static void testFutureProofParser(void)
{
    long ret;

    testDiag("testFutureProofParser()");
    asCheckClientIP = 0;

    eltc(0);  /* Suppress error messages during test */

    /* Test parsing should reject unsupported elements badly placed or formed */
    ret = asInitMem(unsupported_config_1, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects invalid arg list missing commas -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_config_2, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects invalid string list -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_config_3, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects missing parameters (must have at least an empty arg list) -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_config_4, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects bad arg list for recursive body -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_config_5, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects mix of list and recursive type bodies -> %s", errSymMsg(ret));


    /* Test supported elements badly modified should be rejected */
    ret = asInitMem(unsupported_mod_1, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects bad arg list for ASG element -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_mod_2, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects bad arg list for HAG element-> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_mod_3, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects bad arg list for RULE element -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_mod_4, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects bad arg count for ASG element -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_mod_5, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects unexpected name in arg list for RULE element -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_mod_6, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects unexpected recursive body in HAG element body -> %s", errSymMsg(ret));

    ret = asInitMem(unsupported_mod_7, NULL);
    testOk(ret==S_asLib_badConfig, "parsing rejects unexpected recursive body in UAG element body -> %s", errSymMsg(ret));


    eltc(1);

    /* Test supported for known elements containing unsupported elements, well-formed and ignored */
    setUser("testing");
    setHost("localhost");

    ret = asInitMem(supported_config_1, NULL);
    testOk(ret==0, "unknown elements ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 1);
    }

    ret = asInitMem(supported_config_2, NULL);
    testOk(ret==0, "unknown elements with body ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 1);
    }

    ret = asInitMem(supported_config_3, NULL);
    testOk(ret==0, "unknown elements with string and double args and a body, ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 1);
    }

    ret = asInitMem(supported_config_4, NULL);
    testOk(ret==0, "unknown elements with recursive body ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 1);
    }

    ret = asInitMem(supported_config_5, NULL);
    testOk(ret==0, "unknown elements with recursive body with recursion ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 1);
    }

    ret = asInitMem(supported_config_6, NULL);
    testOk(ret==0, "unknown elements with keywords arguments and body names ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ignored", 0);
        testAccess("ro", 1);
    }

    ret = asInitMem(supported_config_7, NULL);
    testOk(ret==0, "rules with unknown elements ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 0);
    }

    ret = asInitMem(supported_config_8, NULL);
    testOk(ret==0, "rules with unknown permission names ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 0);
    }

    ret = asInitMem(supported_config_9, NULL);
    testOk(ret==0, "rules with unknown protocol names ignored -> %s", errSymMsg(ret));
    if (!ret) {
        asAsl = 0;
        testAccess("DEFAULT", 0);
        testAccess("ro", 0);
    }
}

static void testMethodAndAuth(void)
{
    testDiag("testMethodAndAuth()");
    asCheckClientIP = 0;

    testOk1(asInitMem(method_auth_config, NULL)==0);

    asAsl = 0;
    testAccess("DEFAULT", 0);

    setHost("localhost");
    setUser("boss");
    setMethod("ca");

    testAccess("ro", 0);
    testAccess("rw", 0);
    testAccess("rwx", 0);

    setUser("testing");

    testAccess("ro", 1);
    testAccess("rw", 0);
    testAccess("rwx", 0);

    setMethod("x509");

    testAccess("ro", 0);
    testAccess("rw", 0);
    testAccess("rwx", 0);

    setAuthority("Epics Org CA");
    setProtocol(1);

    testAccess("ro", 0);
    testAccess("rw", 3);
    testAccess("rwx", 0);

    setAuthority("ORNL Org CA");
    testAccess("ro", 0);
    testAccess("rw", 0);

    setUser("boss");
    testAccess("rwx", 7);
}

static char* readFile(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    // Seek to the end to determine file size.
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(file);
        return NULL;
    }
    long filesize = ftell(file);
    if (filesize < 0) {
        perror("ftell");
        fclose(file);
        return NULL;
    }
    rewind(file);

    // Allocate a buffer for the file contents plus a null terminator.
    char *buffer = malloc(filesize + 1);
    if (!buffer) {
        perror("malloc");
        fclose(file);
        return NULL;
    }

    // Read the file into the buffer.
    size_t read_size = fread(buffer, 1, filesize, file);
    if (read_size != (size_t)filesize) {
        perror("fread");
        free(buffer);
        fclose(file);
        return NULL;
    }
    buffer[filesize] = '\0';  // Null-terminate the string.

    fclose(file);
    return buffer;
}

static void testDumpOutput(void)
{
    testDiag("testDumpOutput()");
    asCheckClientIP = 0;

    testOk1(asInitMem(method_auth_config, NULL)==0);

    // Create temporary file in current directory
    char temp_filename[] = "aslib_test_XXXXXX";
#ifdef _WIN32
    _mktemp(temp_filename);
    FILE *fp = fopen(temp_filename, "w+");
#else
    int fd = mkstemp(temp_filename);
    testOk(fd != -1, "Created temporary file");
    if (fd == -1) return;
    FILE *fp = fdopen(fd, "w+");
#endif
    testOk(fp != NULL, "Opened temporary file stream");
    if (!fp) {
#ifndef _WIN32
        close(fd);
#endif
        unlink(temp_filename);
        return;
    }

    // Write dump to temporary file
    asDumpFP(fp, NULL, NULL, 0);
    fflush(fp);
    rewind(fp);

    // Read the entire dump into a buffer
    char *buf = readFile(temp_filename);

    testOk(buf != NULL && strcmp(expected_method_auth_config, buf) == 0,
           "asDumpFP output matches expected\nExpected:\n%s\nGot:\n%s",
           expected_method_auth_config, buf ? buf : "NULL");

    // Clean up
    free(buf);
    fclose(fp);
    unlink(temp_filename);  // Delete temporary file
}

static void runRestDumpRules(const char *rule, const char *expected_config)
{
    static char temp_filename[] = "aslib_test_XXXXXX";
#ifdef _WIN32
    _mktemp(temp_filename);
    FILE *fp = fopen(temp_filename, "w+");
#else
    int fd = mkstemp(temp_filename);
    FILE *fp = fdopen(fd, "w+");
#endif
    testOk(fp != NULL, "Opened temporary file for rule %s", rule);
    if (!fp) return;
    asDumpRulesFP(fp, rule);
    fclose(fp);
    char *buf = readFile(temp_filename);
    unlink(temp_filename);
    testOk(strcmp(expected_config, buf) == 0,
           "asDumpFP %s output matches expected\nExpected:\n%s\nGot:\n%s",
           rule, expected_config, buf);
    free(buf);
    strcpy(temp_filename, "aslib_test_XXXXXX");
}

static void testRulesDumpOutput(void)
{
    testDiag("testRulesDumpOutput()");
    asCheckClientIP = 0;

    testOk1(asInitMem(method_auth_config, NULL)==0);

    runRestDumpRules("DEFAULT",  expected_DEFAULT_rules_config);
    runRestDumpRules("ro",  expected_ro_rules_config);
    runRestDumpRules("rw",  expected_rw_rules_config);
    runRestDumpRules("rwx", expected_rwx_rules_config);
}

MAIN(aslibtest)
{
    testPlan(102);
    testSyntaxErrors();
    testHostNames();
    testDumpOutput();
    testRulesDumpOutput();
    testUseIP();
    testFutureProofParser();
    testMethodAndAuth();
    errlogFlush();
    return testDone();
}
