/* SPDX-License-Identifier: EPICS */

#include <stdlib.h>

#include "dbAccess.h"
#include "dbBase.h"
#include "dbStaticLib.h"
#include "dbLoadTemplate.h"

#include "dbUnitTest.h"
#include "testMain.h"

void dbTestIoc_registerRecordDeviceDriver(struct dbBase *);

MAIN(dbSubstYamlLoadTest)
{
    testPlan(0);

    testdbPrepare();

    testdbReadDatabase("dbTestIoc.dbd", NULL, NULL);
    dbTestIoc_registerRecordDeviceDriver(pdbbase);

    testOk1(dbLoadTemplate("../dbSubstYamlLoadTest.substitutions.yaml", NULL, NULL) == 0);

    testIocInitOk();

    testdbGetFieldEqual("DEV:A.DESC", DBR_STRING, "A");
    testdbGetFieldEqual("DEV:B.DESC", DBR_STRING, "B");

    testIocShutdownOk();
    testdbCleanup();
    return testDone();
}
