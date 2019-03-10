/**
 *      @file    testsupp.h
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

#ifndef _h_TESTSUPP_H_
# define _h_TESTSUPP_H_ 1

# ifndef _h_PS_CORECONFIG
#  ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#   include <coreConfig.h> /* Must be first included */
#  else
#   include "coreConfig.h" /* Must be first included */
#  endif
# endif /* _h_PS_CORECONFIG */

#include "cl_header_begin.h"

/* Classification of test results. */
typedef enum { OK, FAILED, WEAK, SKIPPED } TEST_RESULT;

# ifndef TEST_TAG
/* It is recommended to override the tag. */
#  define TEST_TAG TEST
# endif /* TEST_TAG */

# define debugf(x, ...) PS_LOGF_TRACE(TEST_TAG, x ,##__VA_ARGS__ )

/* Internal variable for extended status information. */
extern char extra_info[128];

/* Breakpoint for tests. */
int test(int condition);

/* Breakpoint for failures. */
TEST_RESULT fail(void);

/* Reporting failures. */
TEST_RESULT fail_at(const char *file, int line, const char *cond);

/* Convenience macro for ensuring condition is true. */
#define FAIL_IF(condition)                      \
    do {                                \
        if (test(condition)) {                    \
            return fail_at(__FILE__, __LINE__, #condition); } \
    } while (0)

/* Find tests from command line input. */
int test_match(int argc, char **argv, const char *string);

/* List test. */
# define TEST(fun)                                                 \
    do {                                                           \
        int res;                                                   \
        if (argc == 2 && argv[1] != NULL &&                        \
            !Strcmp(argv[1], "--list")) {                          \
            Printf("%s\n", #fun);                                  \
            break;                                                 \
        } else if (test_match(argc, argv, #fun)) {                 \
            Printf("%s ... ", #fun);                               \
            Fflush(stdout);                                        \
            res = fun();                                           \
            counter[(int) res]++;                                  \
            Printf("%s%s\n", res == OK ? "OK" :                    \
                   res == WEAK ? "OK (but size considered weak)" : \
                   res == SKIPPED ? "OK (not supported)" :         \
                   "FAILED", extra_info);                          \
            extra_info[0] = 0;                                     \
        }                                                          \
    } while (0)

TEST_RESULT ok_partial(const char *file, int line);
#define OK_PARTIAL ok_partial(__FILE__, __LINE__)

extern int counter[4];

/* Provide usual facilities. */
void testsupp_start_test_program(int argc, char **argv);

/* Give test statistics. */
int testsupp_summarize_results(void);

/* Finish test, with handling of a special case: listing of tests.
   Also includes  testsupp_summarize_results() when needed. */
int testsupp_finish(void);

/* Process all tests registered via TestAdd(). */
void testsupp_process(int argc, char **argv);

/* Provide main.
   Without oldstyle tests TESTSUPP_MAIN() will suffice. */
#define TESTSUPP_MAIN(possible_oldstyle_test_and_semicolon) \
int main(int argc, char **argv)                             \
{                                                           \
        testsupp_start_test_program(argc, argv);            \
        testsupp_process(argc, argv);                       \
        possible_oldstyle_test_and_semicolon                \
        return testsupp_finish();                           \
}                                                           \
extern int require_semicolon

/* Alternatively the test needs to implement main function.
   Something like this: */
# ifdef EXAMPLE_MAIN
int main(int argc, char **argv)
{
    testsupp_start_test_program(argc, argv);
    testsupp_process(argc, argv);

    /* Tests can also be executed using the old style:
       Define test function, list it with TEST(). */
    TEST(TEST_OldStyle);

    return testsupp_finish();
}
# endif /* EXAMPLE_MAIN */

/* Internal part: using test entries directly. */

#include "list.h"

/* Defines single test, including its name, function to execute and
   desired outcome. */
struct TestEntry
{
    const char *TestName;
    void *TestParameter;
    enum { TEST_DISABLED, TEST_ENABLED } TestStatus;
    TEST_RESULT TestExpectedResult;
    TEST_RESULT (*TestFunction)(void);
    void (*TestFreeFunction)(void);
    DLListEntry dle;
};

/* Get name of the current test. */
const char *CurrentTestGetName(void);

/* Get parameter (generic void * pointer) of the current test. */
void *CurrentTestGetParameter(void);

/* Add test to list of tests. */
void TestAdd(struct TestEntry *te);

/* Process tests: print or execute them. */
void TestProcess(int argc, char **argv);

/* Clean memory reserved for tests. */
void TestCleanup(void);

/* Default AUTO_TEST parameters. */
extern struct TestEntry AutoTestEntryDefault;

/* Add test to list of tests to perform. */
#define AUTO_TEST_ADD(name) AUTO_TEST_ADD_COMMON(name, )

/* Add test to list, but disable it for now.
   Test will only run if explicitly requested. */
#define AUTO_TEST_ADD_DISABLED(name)                            \
    AUTO_TEST_ADD_COMMON(name, te.TestStatus = TEST_DISABLED;)

/* Add test to list, but expect it to fail.
   This will reverse interpretation of test results. */
#define AUTO_TEST_ADD_XFAIL(name)                               \
    AUTO_TEST_ADD_COMMON(name, te.TestExpectedResult = FAILED;)

/* Define a test and add it to tests to perform. */
#define AUTO_TEST(name) AUTO_TEST_ADD(name); TEST_RESULT name(void)

/* Define a test and add it to list of tests, but do not run it by default. */
#define AUTO_TEST_DISABLED(name)                                \
    AUTO_TEST_ADD_DISABLED(name); TEST_RESULT name(void)

/* Define a test and add it to list of tests.
   The test is expected to fail for now.
   (E.g. missing test or software feature.) */
#define AUTO_TEST_XFAIL(name)                           \
    AUTO_TEST_ADD_XFAIL(name); TEST_RESULT name(void)

/* Worker macros. */
#define AUTO_TEST_ADD_CONCAT_(s_a, s_b) s_a ## s_b
#define AUTO_TEST_ADD_CONCAT(s_a, s_b) AUTO_TEST_ADD_CONCAT_(s_a, s_b)

/* Worker macro, use AUTO_TEST or AUTO_TEST_ADD etc. instead. */
#define AUTO_TEST_ADD_COMMON(name, extra_code)                       \
TEST_RESULT name(void);                                              \
static void AUTO_TEST_ADD_CONCAT(name,_constructor_auto_add)(void)   \
     PS_GCC_SPECIFIC(__attribute__((__constructor__)));              \
                                                                     \
static void AUTO_TEST_ADD_CONCAT(name,_constructor_auto_add)(void)   \
{                                                                    \
    static struct TestEntry te;                                      \
    te.TestName = #name;                                             \
    te.TestParameter = AutoTestEntryDefault.TestParameter;           \
    te.TestStatus = AutoTestEntryDefault.TestStatus;                 \
    te.TestExpectedResult = AutoTestEntryDefault.TestExpectedResult; \
    te.TestFunction = &name;                                         \
    te.TestFreeFunction = AutoTestEntryDefault.TestFreeFunction;     \
    extra_code                                                       \
                                                                     \
    TestAdd(&te);                                                    \
}

/* Examples of tests */
# ifdef DO_NOT_COMPILE_TEST_EXAMPLES

/* These examples intent to illustrate how to use AUTO_TEST and
   its variants. (Note: also remember to use TESTSUPP_MAIN or equivalent. */

AUTO_TEST(TEST_Arithmetic)
{
    FAIL_IF(1 + 1 != 2);
    return OK;
}

AUTO_TEST(TEST_Arithmetic2)
{
    FAIL_IF(1 * 1 != 1);
    return OK;
}

AUTO_TEST_DISABLED(TEST_Arithmetic3)
{
    /* Disabled the test due to a small error in the test. */
    /* Test can be executed if explicitly requested. */
    FAIL_IF(1.5 * 1.5 != 2.0);
    return OK;
}

#include "math.h"
AUTO_TEST_XFAIL(TEST_Arithmetic4)
{
    /* This test fails on most devices, because of math library precision. */
    FAIL_IF(M_PI != 3.14);
    return OK;
}

# endif /* DO_NOT_COMPILE_TEST_EXAMPLES */

#include "cl_header_end.h"

#endif /* testsupp.h */
/* end of file testsupp.h */
