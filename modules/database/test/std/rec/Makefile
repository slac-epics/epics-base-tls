#*************************************************************************
# Copyright (c) 2012 UChicago Argonne LLC, as Operator of Argonne
#     National Laboratory.
# Copyright (c) 2002 The Regents of the University of California, as
#     Operator of Los Alamos National Laboratory.
# EPICS BASE is distributed subject to a Software License Agreement found
# in the file LICENSE that is included with this distribution.
#*************************************************************************

TOP = ../../../../..
include $(TOP)/configure/CONFIG

USR_CPPFLAGS += -DUSE_TYPED_RSET
USR_CPPFLAGS += -DUSE_TYPED_DSET

TESTLIBRARY = dbRecStdTest

dbRecStdTest_SRCS += asTestLib.c
dbRecStdTest_LIBS += dbRecStd dbCore ca Com

PROD_LIBS = dbRecStdTest dbRecStd dbCore ca Com

TARGETS += $(COMMON_DIR)/recTestIoc.dbd
ifneq (inc,$(strip $(MAKECMDGOALS)))
DBDDEPENDS_FILES += recTestIoc.dbd$(DEP)
endif
recTestIoc_DBD = base.dbd
recTestIoc_DBD += bptTypeKdegC.dbd
recTestIoc_DBD += bptTypeKdegF.dbd
recTestIoc_DBD += bptTypeJdegF.dbd
recTestIoc_DBD += bptTypeJdegC.dbd

TESTFILES += $(COMMON_DIR)/recTestIoc.dbd

testHarness_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += asTestIoc_registerRecordDeviceDriver.cpp

TESTPROD_HOST += arrayOpTest
arrayOpTest_SRCS += arrayOpTest.c
arrayOpTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += arrayOpTest.c
TESTFILES += ../arrayOpTest.db
TESTS += arrayOpTest

TESTPROD_HOST += recMiscTest
recMiscTest_SRCS += recMiscTest.c
recMiscTest_CFLAGS_NO = -DLINK_DYNAMIC
recMiscTest_CFLAGS += $(recMiscTest_CFLAGS_$(STATIC_BUILD))
recMiscTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += recMiscTest.c
TESTFILES += ../recMiscTest.db
TESTS += recMiscTest

TESTPROD_HOST += linkRetargetLinkTest
linkRetargetLinkTest_SRCS += linkRetargetLinkTest.c
linkRetargetLinkTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += linkRetargetLinkTest.c
TESTFILES += ../linkRetargetLink.db
TESTS += linkRetargetLinkTest

TESTPROD_HOST += linkInitTest
linkInitTest_SRCS += linkInitTest.c
linkInitTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += linkInitTest.c
TESTFILES += ../linkInitTest.db
TESTS += linkInitTest

TESTPROD_HOST += compressTest
compressTest_SRCS += compressTest.c
compressTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += compressTest.c
TESTFILES += ../compressTest.db
TESTS += compressTest

TESTPROD_HOST += asyncSoftTest
asyncSoftTest_SRCS += asyncSoftTest.c
asyncSoftTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += asyncSoftTest.c
TESTFILES += ../asyncSoftTest.db
TESTS += asyncSoftTest

TESTPROD_HOST += softTest
softTest_SRCS += softTest.c
softTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += softTest.c
TESTFILES += ../softTest.db
TESTS += softTest

TESTPROD_HOST += seqTest
seqTest_SRCS += seqTest.c
seqTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += seqTest.c
TESTFILES += ../seqTest.db
TESTS += seqTest

TESTPROD_HOST += longoutTest
longoutTest_SRCS += longoutTest.c
longoutTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += longoutTest.c
TESTFILES += ../longoutTest.db
TESTS += longoutTest

TESTPROD_HOST += boTest
boTest_SRCS += boTest.c
boTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += boTest.c
TESTFILES += ../boTest.db
TESTS += boTest

TESTPROD_HOST += biTest
biTest_SRCS += biTest.c
biTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += biTest.c
TESTFILES += ../biTest.db
TESTS += biTest

TESTPROD_HOST += printfTest
printfTest_SRCS += printfTest.c
printfTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += printfTest.c
TESTFILES += ../printfTest.db
TESTS += printfTest

TESTPROD_HOST += aiTest
aiTest_SRCS += aiTest.c
aiTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += aiTest.c
TESTFILES += ../aiTest.db
TESTS += aiTest

TARGETS += $(COMMON_DIR)/asTestIoc.dbd
DBDDEPENDS_FILES += asTestIoc.dbd$(DEP)
asTestIoc_DBD += base.dbd
asTestIoc_DBD += asTest.dbd
TESTPROD_HOST += asTest
asTest_SRCS += asTest.c
asTest_SRCS += asTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += asTest.c
TESTFILES += $(COMMON_DIR)/asTestIoc.dbd ../asTest.db
TESTS += asTest

TARGETS += $(COMMON_DIR)/analogMonitorTest.dbd
DBDDEPENDS_FILES += analogMonitorTest.dbd$(DEP)
analogMonitorTest_DBD += base.dbd
TESTPROD_HOST += analogMonitorTest
analogMonitorTest_SRCS += analogMonitorTest.c
analogMonitorTest_SRCS += analogMonitorTest_registerRecordDeviceDriver.cpp
testHarness_SRCS += analogMonitorTest.c
testHarness_SRCS += analogMonitorTest_registerRecordDeviceDriver.cpp
TESTFILES += $(COMMON_DIR)/analogMonitorTest.dbd ../analogMonitorTest.db
TESTS += analogMonitorTest

TARGETS += $(COMMON_DIR)/scanEventTest.dbd
DBDDEPENDS_FILES += scanEventTest.dbd$(DEP)
scanEventTest_DBD += base.dbd
TESTPROD_HOST += scanEventTest
scanEventTest_SRCS += scanEventTest.c
scanEventTest_SRCS += scanEventTest_registerRecordDeviceDriver.cpp
testHarness_SRCS += scanEventTest.c
testHarness_SRCS += scanEventTest_registerRecordDeviceDriver.cpp
TESTFILES += $(COMMON_DIR)/scanEventTest.dbd ../scanEventTest.db
TESTS += scanEventTest

TARGETS += $(COMMON_DIR)/regressTest.dbd
DBDDEPENDS_FILES += regressTest.dbd$(DEP)
regressTest_DBD += base.dbd
TESTPROD_HOST += regressTest
regressTest_SRCS += regressTest.c
regressTest_SRCS += regressTest_registerRecordDeviceDriver.cpp
TESTFILES += $(COMMON_DIR)/regressTest.dbd ../regressArray1.db ../regressHex.db ../regressLinkMS.db
TESTFILES += ../badCaLink.db
TESTFILES += ../regressLongCalc.db
TESTFILES += ../regressLinkSevr.db
TESTS += regressTest

TARGETS += $(COMMON_DIR)/simmTest.dbd
TARGETS += $(COMMON_DIR)/simmTest.db
DBDDEPENDS_FILES += simmTest.dbd$(DEP)
ifneq (inc,$(strip $(MAKECMDGOALS)))
DBDDEPENDS_FILES += simmTest.db$(DEP)
endif
simmTest_DBD += base.dbd
TESTPROD_HOST += simmTest
simmTest_SRCS += simmTest.c
simmTest_SRCS += simmTest_registerRecordDeviceDriver.cpp
testHarness_SRCS += simmTest.c
testHarness_SRCS += simmTest_registerRecordDeviceDriver.cpp
TESTFILES += $(COMMON_DIR)/simmTest.dbd $(COMMON_DIR)/simmTest.db
TESTS += simmTest

TESTPROD_HOST += mbbioDirectTest
mbbioDirectTest_SRCS += mbbioDirectTest.c
mbbioDirectTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += mbbioDirectTest.c
TESTFILES += ../mbbioDirectTest.db
TESTS += mbbioDirectTest

TARGETS += $(COMMON_DIR)/asyncproctest.dbd
DBDDEPENDS_FILES += asyncproctest.dbd$(DEP)
asyncproctest_DBD += base.dbd
TESTPROD_HOST += asyncproctest
asyncproctest_SRCS += asyncproctest.c
asyncproctest_SRCS += asyncproctest_registerRecordDeviceDriver.cpp
TESTFILES += $(COMMON_DIR)/asyncproctest.dbd ../asyncproctest.db
TESTS += asyncproctest

TARGETS += $(COMMON_DIR)/subproctest.dbd
DBDDEPENDS_FILES += subproctest.dbd$(DEP)
subproctest_DBD += base.dbd
TESTPROD_HOST += subproctest
subproctest_SRCS += subproctest.c
subproctest_SRCS += subproctest_registerRecordDeviceDriver.cpp
TESTFILES += $(COMMON_DIR)/subproctest.dbd ../subproctest.db
TESTS += subproctest


TESTPROD_HOST += linkFilterTest
linkFilterTest_SRCS += linkFilterTest.c
linkFilterTest_SRCS += recTestIoc_registerRecordDeviceDriver.cpp
testHarness_SRCS += linkFilterTest.c
TESTFILES += ../linkFilterTest.db
TESTS += linkFilterTest

# These are compile-time tests, no need to link or run
TARGETS += dbHeaderTest$(OBJ)
TARGET_SRCS += dbHeaderTest.cpp
TARGETS += dbHeaderTestxx$(OBJ)
TARGET_SRCS += dbHeaderTestxx.cpp

ifeq ($(T_A),$(EPICS_HOST_ARCH))
# Host-only tests of softIoc/softIocPVA, caget and pvget (if present)
# Unfortunately hangs too often on CI systems:
ifndef CI
TESTS += netget
endif
endif

# epicsRunRecordTests runs all the test programs in a known working order.
testHarness_SRCS += epicsRunRecordTests.c

recordTestHarness_SRCS += $(testHarness_SRCS)
recordTestHarness_SRCS_RTEMS += rtemsTestHarness.c

PROD_SRCS_RTEMS += rtemsTestData.c

PROD_vxWorks = recordTestHarness
PROD_RTEMS = recordTestHarness

TESTSPEC_vxWorks = recordTestHarness.munch; epicsRunRecordTests
TESTSPEC_RTEMS = recordTestHarness.boot; epicsRunRecordTests

TESTSCRIPTS_HOST += $(TESTS:%=%.t)
ifneq ($(filter $(T_A),$(CROSS_COMPILER_RUNTEST_ARCHS)),)
TESTPROD += $(TESTPROD_HOST)
TESTSCRIPTS += $(TESTS:%=%.t)
endif

include $(TOP)/configure/RULES

rtemsTestData.c : $(TESTFILES) $(TOOLS)/epicsMakeMemFs.pl
	$(PERL) $(TOOLS)/epicsMakeMemFs.pl $@ epicsRtemsFSImage $(TESTFILES)
