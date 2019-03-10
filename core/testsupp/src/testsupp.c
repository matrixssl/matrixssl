/**
 *      @file    testsupp.c
 *      @version $Format:%h%d$
 *
 *      Common testing framework for building test programs.
 */
/*
 *      Copyright (c) 2017-2018 INSIDE Secure Corporation
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

/* Note: This program is intended to run with all logging messages on. */

#ifndef _h_PS_CORECONFIG
# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <coreConfig.h> /* Must be first included */
# else
#  include "coreConfig.h" /* Must be first included */
# endif
#endif /* _h_PS_CORECONFIG */

#include "coreApi.h"
#include "psUtil.h"

#include "osdep_stdio.h"
#include "osdep_stdlib.h"
#include "osdep_limits.h"
#include "psPrnf.h"
#include "sfzcl/sfzclsnprintf.h"
#include "cf_impldefs.h"

/* Enable following if you wish to test effect of flags to
   PS_NO_LOGF processing.
#undef PS_NO_LOGF_FILELINE
#define PS_NO_LOGF_FILELINE
#undef PS_NO_LOGF_PRINT_UNIT
#define PS_NO_LOGF_PRINT_UNIT
*/

#define PS_LOGF_WITH_PRNF
#include "psLog.h" /* SafeZone/Matrix common logging framework */

#include "testsupp.h"

/* Storage for extraneous info. */
char extra_info[128];

int test(int condition)
{
    /* This function is provided as convenience for setting
       breakpoint(s). */
    return condition;
}

TEST_RESULT fail(void)
{
    /* This function is provided as convenience for setting
       breakpoint(s). */
    return FAILED;
}

TEST_RESULT fail_at(const char *file, int line, const char *cond)
{
    /* This function is provided as convenience for setting
       breakpoint(s) and for debug output. */
    Fprintf(stderr, "Failure detected at %s:%d: %s\n", file, line, cond);
    return fail();
}

#define FAIL_IF(condition)                      \
    do {                                \
        if (test(condition)) {                    \
            return fail_at(__FILE__, __LINE__, #condition); } \
    } while (0)

int test_match(int argc, char **argv, const char *string)
{
    int i;

    if (argc == 1)
    {
        return 1;
    }

    for (i = 1; i < argc; i++)
    {
        if (argv[i] != NULL && !psStrCaseCmp(argv[i], string))
        {
            argv[i] = NULL;
            return 2; /* Explicitly requested. */
        }
    }

    return 0;
}

TEST_RESULT ok_partial(const char *file, int line)
{
    Snprintf(extra_info, sizeof(extra_info),
             "(PARTIAL [see %s:%d for details])", file, line);
    return OK;
}

/* Test counters: start at zero. */
int counter[4] = { 0, 0, 0, 0 };

int testsupp_summarize_results(void)
{
    int counter_sum = counter[(int) OK] + counter[(int) WEAK] +
        counter[(int) FAILED];
    counter[(int) OK] += counter[(int) WEAK];

    if (counter_sum == 0)
    {
        Printf("No tests. (Maybe configuration or build error?)\n");
    }
    else
    {
        Printf("Tests with expected result: %d/%d\n",
               counter[(int) OK], counter_sum );
        if (counter[(int) FAILED])
        {
            Printf("Unexpected results: %d/%d\n",
                   counter[(int) FAILED], counter_sum);
        }
    }

    return counter[(int) OK] == 0 || counter[(int) FAILED] != 0;
}

void testsupp_start_test_program(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* This function may provide what ever services are usually needed
       for debugging and/or other testing.*/

    /* Currently the provided code: provide malloc tracing if needed. */
#ifdef USE_MTRACE
    if (Getenv("MALLOC_TRACE"))
    {
        mtrace();
    }
#endif /* USE_MTRACE */
}

static DEFINE_DLLIST(TestsList);
static struct TestEntry *currentTest = NULL;
static int TestPrintingOnly = 0;

const char *CurrentTestGetName(void)
{
    return currentTest ? currentTest->TestName : NULL;
}

void *CurrentTestGetParameter(void)
{
    return currentTest ? currentTest->TestParameter : NULL;
}

void TestAdd(struct TestEntry *te)
{
    DLListInsertTail(&TestsList, &te->dle);
}

static
void TestExecuteTe(struct TestEntry *te)
{
    TEST_RESULT res;

    if (currentTest != NULL)
    {
        PS_LOGF_FATAL(TEST_FRAMEWORK,
                      "Test %s is already running.\n", CurrentTestGetName());
        PS_LOGF_FATAL(TEST_FRAMEWORK,
                      "Fatal failure starting %s.\n", te->TestName);
        Abort();
    }

    Assert(te->TestName);
    Assert(te->TestFunction);

    currentTest = te;
    Printf("%s ... ", CurrentTestGetName());
    Fflush(stdout);
    res = te->TestFunction();
    if ((res == OK || res == WEAK) && te->TestExpectedResult == FAILED)
    {
        Strcpy(extra_info, " (EXPECTED: FAILURE)");
        counter[(int) FAILED]++;
    }
    else if (res == FAILED && te->TestExpectedResult == FAILED)
    {
        Strcpy(extra_info, " (EXPECTED FAILURE: Test considered OK)");
        counter[(int) OK]++;
    }
    else
    {
        counter[(int) res]++;
    }
    Printf("%s%s\n", res == OK ? "OK" :
           res == WEAK ? "OK (but size considered weak)" :
           res == SKIPPED ? "OK (not supported)" :
           "FAILED", extra_info);
    currentTest = NULL;
    extra_info[0] = 0;
}

void TestProcess(int argc, char **argv)
{
    DLListEntry *pList;

    pList = TestsList.pNext;
    while (pList != &TestsList)
    {
        struct TestEntry *te = DLListGetContainer(pList, struct TestEntry, dle);

        if (TestPrintingOnly)
        {
            printf("%s%s\n",
                   te->TestName,
                   te->TestStatus == TEST_ENABLED ? "" : " (disabled)");
        }
        else
        {
            int res = test_match(argc, argv, te->TestName);

            /* Execute test. */
            if ((argc < 2 && te->TestStatus == TEST_ENABLED) ||
                (res > 0 && te->TestStatus == TEST_ENABLED) ||
                res > 1)
            {
                TestExecuteTe(te);
            }
        }
        pList = pList->pNext;
    }
}

void TestCleanup(void)
{
    while (!DLListIsEmpty(&TestsList))
    {
        DLListEntry *pList;
        struct TestEntry *te;
    
        pList = DLListGetHead(&TestsList);
        te = DLListGetContainer(pList, struct TestEntry, dle);
        if (te->TestFreeFunction)
        {
            te->TestFreeFunction();
        }
    }
}

void testsupp_process(int argc, char **argv)
{
    if (argc == 2 && argv[1] != NULL &&
        !Strcmp(argv[1], "--list"))
    {
        Printf("Test available:\n");
        TestPrintingOnly = 1;
    }
            
    TestProcess(argc, argv);
    TestCleanup();
}


/* Default auto_test parameters. */
struct TestEntry AutoTestEntryDefault =
{
    "(name)",
    NULL,
    TEST_ENABLED,
    OK,
    NULL,
    NULL
};

/* Finish test, with handling of a special case: listing of tests. */
int testsupp_finish(void)
{
    if (TestPrintingOnly)
    {
        return 0;
    }

    return testsupp_summarize_results();
}


/* end of file testsupp.c */
