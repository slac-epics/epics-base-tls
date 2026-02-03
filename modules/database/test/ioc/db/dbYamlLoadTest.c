/* SPDX-License-Identifier: EPICS */

#include <stdlib.h>

#include "dbAccess.h"
#include "dbBase.h"
#include "dbStaticLib.h"

#include "dbUnitTest.h"
#include "testMain.h"

void dbTestIoc_registerRecordDeviceDriver(struct dbBase *);

MAIN(dbYamlLoadTest)
{
    testPlan(0);

    testdbPrepare();

    testdbReadDatabase("dbTestIoc.dbd", NULL, NULL);
    dbTestIoc_registerRecordDeviceDriver(pdbbase);
    testdbReadDatabase("dbYamlLoadTest.db.yaml", NULL, NULL);
    testIocInitOk();

    testdbGetFieldEqual("yamldb.VAL", DBR_STRING, "1");

    testIocShutdownOk();

    testdbCleanup();
    return testDone();
}
