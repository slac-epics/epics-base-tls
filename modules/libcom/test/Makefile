#*************************************************************************
# Copyright (c) 2006 The University of Chicago, as Operator of Argonne
#     National Laboratory.
# Copyright (c) 2002 The Regents of the University of California, as
#     Operator of Los Alamos National Laboratory.
# EPICS BASE is distributed subject to a Software License Agreement found
# in file LICENSE that is included with this distribution.
#*************************************************************************

TOP = ../../..
include $(TOP)/configure/CONFIG

PROD_LIBS += Com
PROD_SYS_LIBS_WIN32 += ws2_32 advapi32 user32
PROD_SYS_LIBS_solaris += socket nsl

PROD_SRCS_RTEMS += rtemsTestData.c

ifeq ($(EPICS_HOST_ARCH),$(T_A))
# skip except for host arch due to custom .plt

TESTPROD_HOST += epicsUnitTestTest
epicsUnitTestTest_SRCS += epicsUnitTestTest.c
# Not much point running this on vxWorks or RTEMS...
TESTS += epicsUnitTestTest

endif

TESTPROD_HOST += epicsTypesTest
epicsTypesTest_SRCS += epicsTypesTest.cpp
testHarness_SRCS += epicsTypesTest.cpp
TESTS += epicsTypesTest

TESTPROD_HOST += epicsInlineTest
epicsInlineTest_SRCS += epicsInlineTest1.c
epicsInlineTest_SRCS += epicsInlineTest2.c
epicsInlineTest_SRCS += epicsInlineTest3.cpp
epicsInlineTest_SRCS += epicsInlineTest4.cpp
testHarness_SRCS += $(epicsInlineTest_SRCS)
TESTS += epicsInlineTest

TESTPROD_HOST += epicsCalcTest
epicsCalcTest_SRCS += epicsCalcTest.cpp
testHarness_SRCS += epicsCalcTest.cpp
TESTS += epicsCalcTest

TESTPROD_HOST += epicsAlgorithmTest
epicsAlgorithmTest_SRCS += epicsAlgorithmTest.cpp
testHarness_SRCS += epicsAlgorithmTest.cpp
TESTS += epicsAlgorithmTest

TESTPROD_HOST += epicsMathTest
epicsMathTest_SRCS += epicsMathTest.c
testHarness_SRCS += epicsMathTest.c
TESTS += epicsMathTest

TESTPROD_HOST += epicsMMIOTest
epicsMMIOTest_SRCS += epicsMMIOTest.c
testHarness_SRCS += epicsMMIOTest.c
TESTS += epicsMMIOTest

TESTPROD_HOST += epicsEllTest
epicsEllTest_SRCS += epicsEllTest.c
testHarness_SRCS += epicsEllTest.c
TESTS += epicsEllTest

TESTPROD_HOST += epicsEnvTest
epicsEnvTest_SRCS += epicsEnvTest.c
testHarness_SRCS += epicsEnvTest.c
TESTS += epicsEnvTest

TESTPROD_HOST += epicsEnvUnsetTest
epicsEnvUnsetTest_SRCS += epicsEnvUnsetTest.c
testHarness_SRCS += epicsEnvUnsetTest.c
TESTS += epicsEnvUnsetTest

TESTPROD_HOST += epicsErrlogTest
epicsErrlogTest_SRCS += epicsErrlogTest.c
testHarness_SRCS += epicsErrlogTest.c
TESTS += epicsErrlogTest

TESTPROD_HOST += epicsStdioTest
epicsStdioTest_SRCS += epicsStdioTest.c
testHarness_SRCS += epicsStdioTest.c
TESTS += epicsStdioTest

TESTPROD_HOST += epicsStdlibTest
epicsStdlibTest_SRCS += epicsStdlibTest.c
testHarness_SRCS += epicsStdlibTest.c
TESTS += epicsStdlibTest

TESTPROD_HOST += epicsSockResolveTest
epicsSockResolveTest_SRCS += epicsSockResolveTest.c
testHarness_SRCS += epicsSockResolveTest.c
TESTS += epicsSockResolveTest

TESTPROD_HOST += epicsStringTest
epicsStringTest_SRCS += epicsStringTest.c
testHarness_SRCS += epicsStringTest.c
TESTS += epicsStringTest

TESTPROD_HOST += epicsTimeTest
epicsTimeTest_SRCS += epicsTimeTest.cpp
testHarness_SRCS += epicsTimeTest.cpp
TESTS += epicsTimeTest

TESTPROD_HOST += epicsTimeZoneTest
epicsTimeZoneTest_SRCS += epicsTimeZoneTest.c
libComTestHarness_SRCS_RTEMS += epicsTimeZoneTest.c
TESTS += epicsTimeZoneTest

TESTPROD_HOST += epicsThreadTest
epicsThreadTest_SRCS += epicsThreadTest.cpp
testHarness_SRCS += epicsThreadTest.cpp
TESTS += epicsThreadTest

TESTPROD_HOST += epicsThreadClassTest
epicsThreadClassTest_SRCS += epicsThreadClassTest.cpp
testHarness_SRCS += epicsThreadClassTest.cpp
TESTS += epicsThreadClassTest

TESTPROD_HOST += epicsThreadOnceTest
epicsThreadOnceTest_SRCS += epicsThreadOnceTest.c
testHarness_SRCS += epicsThreadOnceTest.c
TESTS += epicsThreadOnceTest

TESTPROD_HOST += epicsThreadPriorityTest
epicsThreadPriorityTest_SRCS += epicsThreadPriorityTest.cpp
testHarness_SRCS += epicsThreadPriorityTest.cpp
TESTS += epicsThreadPriorityTest

TESTPROD_HOST += epicsThreadPrivateTest
epicsThreadPrivateTest_SRCS += epicsThreadPrivateTest.cpp
testHarness_SRCS += epicsThreadPrivateTest.cpp
TESTS += epicsThreadPrivateTest

TESTPROD_HOST += epicsThreadHooksTest
epicsThreadHooksTest_SRCS += epicsThreadHooksTest.c
testHarness_SRCS += epicsThreadHooksTest.c
TESTS += epicsThreadHooksTest

TESTPROD_HOST += epicsThreadPoolTest
epicsThreadPoolTest_SRCS += epicsThreadPoolTest.c
testHarness_SRCS += epicsThreadPoolTest.c
TESTS += epicsThreadPoolTest

TESTPROD_HOST += initHookTest
initHookTest_SRCS += initHookTest.c
testHarness_SRCS += initHookTest.c
TESTS += initHookTest

TESTPROD_HOST += epicsExitTest
epicsExitTest_SRCS += epicsExitTest.c
testHarness_SRCS += epicsExitTest.c
TESTS += epicsExitTest

TESTPROD_HOST += epicsTimerTest
epicsTimerTest_SRCS += epicsTimerTest.cpp
testHarness_SRCS += epicsTimerTest.cpp
TESTS += epicsTimerTest

TESTPROD_HOST += ringPointerTest
ringPointerTest_SRCS += ringPointerTest.c
testHarness_SRCS += ringPointerTest.c
TESTS += ringPointerTest

TESTPROD_HOST += ringBytesTest
ringBytesTest_SRCS += ringBytesTest.c
testHarness_SRCS += ringBytesTest.c
TESTS += ringBytesTest

TESTPROD_HOST += epicsEventTest
epicsEventTest_SRCS += epicsEventTest.cpp
testHarness_SRCS += epicsEventTest.cpp
TESTS += epicsEventTest

TESTPROD_HOST += epicsMutexTest
epicsMutexTest_SRCS += epicsMutexTest.cpp
testHarness_SRCS += epicsMutexTest.cpp
TESTS += epicsMutexTest

TESTPROD_HOST += epicsSpinTest
epicsSpinTest_SRCS += epicsSpinTest.c
testHarness_SRCS += epicsSpinTest.c
TESTS += epicsSpinTest

TESTPROD_HOST += epicsAtomicTest
epicsAtomicTest_SRCS += epicsAtomicTest.cpp
testHarness_SRCS += epicsAtomicTest.cpp
TESTS += epicsAtomicTest

TESTPROD_HOST += macDefExpandTest
macDefExpandTest_SRCS += macDefExpandTest.c
testHarness_SRCS += macDefExpandTest.c
TESTS += macDefExpandTest

TESTPROD_HOST += cvtFastTest
cvtFastTest_SRCS += cvtFastTest.cpp
testHarness_SRCS += cvtFastTest.cpp
TESTS += cvtFastTest

TESTPROD_HOST += macLibTest
macLibTest_SRCS += macLibTest.c
testHarness_SRCS += macLibTest.c
TESTS += macLibTest

TESTPROD_HOST += aslibtest
aslibtest_SRCS += aslibtest.c
testHarness_SRCS += aslibtest.c
TESTS += aslibtest

# Perl module tests:
TESTS += macLib

TESTPROD_HOST += taskwdTest
taskwdTest_SRCS += taskwdTest.c
testHarness_SRCS += taskwdTest.c
TESTS += taskwdTest

TESTPROD_HOST += blockingSockTest
blockingSockTest_SRCS += blockingSockTest.cpp
testHarness_SRCS += blockingSockTest.cpp
TESTS += blockingSockTest

TESTPROD_HOST += epicsMessageQueueTest
epicsMessageQueueTest_SRCS += epicsMessageQueueTest.cpp
testHarness_SRCS += epicsMessageQueueTest.cpp
TESTS += epicsMessageQueueTest

# we need to build this with debug symbols in all configurations
# otherwise the test will not be able to lookup names and so fail
TESTPROD_HOST += epicsStackTraceTest
epicsStackTraceTest_SRCS += epicsStackTraceTest.c
ifneq ($(findstring mingw,$(T_A)),)
epicsStackTraceTest_CFLAGS_WIN32 += -g -O0
epicsStackTraceTest_LDFLAGS_WIN32 += -g
else
epicsStackTraceTest_CFLAGS_WIN32 += -Zi
epicsStackTraceTest_LDFLAGS_WIN32 += -DEBUG
endif
testHarness_SRCS += epicsStackTraceTest.c
TESTS += epicsStackTraceTest

TESTPROD_HOST += ipAddrToAsciiTest
ipAddrToAsciiTest_SRCS += ipAddrToAsciiTest.cpp
testHarness_SRCS += ipAddrToAsciiTest.cpp
TESTS += ipAddrToAsciiTest

TESTPROD_HOST += osiSockTest
osiSockTest_SRCS += osiSockTest.c
testHarness_SRCS += osiSockTest.c
TESTS += osiSockTest

TESTPROD_HOST += testexecname
testexecname_SRCS += testexecname.c
# no point in including in testHarness.  Not implemented for RTEMS/vxWorks.
TESTS += testexecname

ifeq ($(BUILD_CLASS),HOST)
ifneq ($(OS_CLASS),WIN32)
# This test can only be run on a build host, and is broken on Windows
TESTPROD_HOST += yajl_test
yajl_test_SRCS += yajl_test.c
TESTS += yajlTest
endif
endif

TESTPROD_HOST += iocshTest
iocshTest_SRCS += iocshTest.cpp
TESTS += iocshTest
TESTFILES += $(wildcard ../iocshTest*.cmd)
TESTFILES += ../iocshTestHelpFunction1 ../iocshTestHelpFunctions

TESTPROD_HOST += epicsLoadTest
epicsLoadTest_SRCS += epicsLoadTest.cpp
# test linked against static libCom?
epicsLoadTest_CPPFLAGS_STATIC_YES = -DLINKING_STATIC
epicsLoadTest_CPPFLAGS += $(epicsLoadTest_CPPFLAGS_STATIC_$(STATIC_BUILD))
# are dynamic libraries built?
epicsLoadTest_CPPFLAGS_SHARED_YES = -DBUILDING_SHARED_LIBRARIES
epicsLoadTest_CPPFLAGS += $(epicsLoadTest_CPPFLAGS_SHARED_$(SHARED_LIBRARIES))
TESTS += epicsLoadTest

# The testHarness runs all the test programs in a known working order.
testHarness_SRCS += epicsRunLibComTests.c

libComTestHarness_SRCS += $(testHarness_SRCS)
libComTestHarness_SRCS_RTEMS += rtemsTestHarness.c

PROD_vxWorks = libComTestHarness
PROD_RTEMS += libComTestHarness

TESTSPEC_vxWorks = libComTestHarness.munch; epicsRunLibComTests
TESTSPEC_RTEMS = libComTestHarness.boot; epicsRunLibComTests

TESTSCRIPTS_HOST += $(TESTS:%=%.t)
ifneq ($(filter $(T_A),$(CROSS_COMPILER_RUNTEST_ARCHS)),)
TESTPROD += $(TESTPROD_HOST)
TESTSCRIPTS += $(filter-out epicsUnitTestTest.t, $(TESTS:%=%.t))
endif


# The following are not test programs, they measure performance.
# They should not be added to TESTS or to epicsRunLibComTests.c

TESTPROD_HOST += epicsThreadPerform
epicsThreadPerform_SRCS += epicsThreadPerform.cpp
testHarness_SRCS += epicsThreadPerform.cpp

TESTPROD_HOST += epicsMaxThreads
epicsMaxThreads_SRCS += epicsMaxThreads.c
testHarness_SRCS += epicsMaxThreads.c

TESTPROD_HOST += buckTest
buckTest_SRCS += buckTest.c
testHarness_SRCS += buckTest.c

#TESTPROD_HOST += fdmgrTest
fdmgrTest_SRCS += fdmgrTest.c
fdmgrTest_LIBS += ca
# FIXME: program never exits.

TESTPROD_HOST += epicsAtomicPerform
epicsAtomicPerform_SRCS += epicsAtomicPerform.cpp
testHarness_SRCS += epicsAtomicPerform.cpp

TESTPROD_HOST += cvtFastPerform
cvtFastPerform_SRCS += cvtFastPerform.cpp
testHarness_SRCS += cvtFastPerform.cpp

ifeq ($(OS_CLASS),Linux)
ifeq ($(USE_POSIX_THREAD_PRIORITY_SCHEDULING),YES)
TESTPROD_HOST += nonEpicsThreadPriorityTest
nonEpicsThreadPriorityTest_SRCS += nonEpicsThreadPriorityTest.cpp
nonEpicsThreadPriorityTest_SYS_LIBS += $(POSIX_LDLIBS:-l%=%)
testHarness_SRCS += nonEpicsThreadPriorityTest.cpp
epicsRunLibComTests_CFLAGS += -DHAVE_PTHREAD_PRIORITY_SCHEDULING
TESTS += nonEpicsThreadPriorityTest
endif
endif

include $(TOP)/configure/RULES

rtemsTestData.c : $(TESTFILES) $(TOOLS)/epicsMakeMemFs.pl
	$(PERL) $(TOOLS)/epicsMakeMemFs.pl $@ epicsRtemsFSImage $(TESTFILES)

epicsLoadTest$(DEP): epicsInstallDir.h

# use INSTALL_LOCATION instead of FINAL_LOCATION since test executables are not installed.
epicsInstallDir.h: $(TOP)/configure/CONFIG_SITE*
	$(ECHO) "INSTALL_LOCATION=$(INSTALL_LOCATION)"
	$(PERL) $(TOP)/modules/database/src/std/softIoc/makeInstallDir.pl "$(INSTALL_LOCATION)" > $@
