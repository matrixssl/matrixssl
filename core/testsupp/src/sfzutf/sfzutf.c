/* sfzutf.c
 *
 * Description: SFZUTF implementation file.
 */

/*****************************************************************************
* Copyright (c) 2007-2016 INSIDE Secure Oy. All Rights Reserved.
*
* The latest version of this code is available at http://www.matrixssl.org
*
* This software is open source; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This General Public License does NOT permit incorporating this software
* into proprietary programs.  If you are unable to comply with the GPL, a
* commercial license for this software may be purchased from INSIDE at
* http://www.insidesecure.com/
*
* This program is distributed in WITHOUT ANY WARRANTY; without even the
* implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#include "sfzutf.h"                 /* the API to implement */
#include "sfzutf_internal.h"

static bool sfzutf_UnsupportedFlag = false;

struct TestSuite *sfzutf_current_suite = NULL;
struct TestCase *sfzutf_current_tcase = NULL;

void
sfzutf_unsupported_quick(void)
{
    ASSERT(sfzutf_UnsupportedFlag == false);
    sfzutf_UnsupportedFlag = true;
}

bool
sfzutf_unsupported_quick_process(void)
{
    bool returnValue = sfzutf_UnsupportedFlag;

    sfzutf_UnsupportedFlag = false;
    return returnValue;
}

void *
sfzutf_AssertNotNull(
    const void *input)
{
    if (!input)
    {
        SFZUTF_PANIC("Bailing out due to insuccessful memory allocation.");
    }
    return (void *) input;
}

/* Single linked list, newly added is the last member. */
void
NodeAdd(struct TestList *List_p, void *Node_p)
{
    struct TestNode *Iterate_p;

    PRECONDITION(List_p != NULL); /* List cannot be NULL. */
    if (Node_p == NULL)
    {
        return;                   /* Allow calling with NULL Node. */

    }
    Iterate_p = (struct TestNode *) List_p;

    while (Iterate_p->NextNode_p != NULL)
    {
        Iterate_p = Iterate_p->NextNode_p;
    }
    Iterate_p->NextNode_p = Node_p;
}

void
sfzutf_suite_create(
    const char *name)
{
    SFZUTF_ASSERT(sfzutf_current_suite == NULL);
    sfzutf_current_suite = sfzutf_AssertNotNull(SFZUTF_CALLOC(sizeof(struct TestSuite), 1));
    sfzutf_current_suite->Name_p = name;
}

void
sfzutf_tcase_finish(void)
{
    SFZUTF_ASSERT(sfzutf_current_suite != NULL);
    if (sfzutf_current_tcase)
    {
        NodeAdd((struct TestList *) &(sfzutf_current_suite->TestCaseList_p), sfzutf_current_tcase);
        sfzutf_current_tcase = NULL;
    }
}

void
sfzutf_tcase_create(
    const char *name)
{
    SFZUTF_ASSERT(sfzutf_current_suite != NULL);
    if (sfzutf_current_tcase != NULL)
    {
        if (SFZUTF_STREQ(sfzutf_current_tcase->Name_p, name))
        {
            /* same tcase name */
            /* just add to current test case */
            return;
        }

        sfzutf_tcase_finish();
    }
    sfzutf_current_tcase = sfzutf_AssertNotNull(SFZUTF_CALLOC(sizeof(struct TestCase), 1));
    sfzutf_current_tcase->Name_p = name;
}

void
sfzutf_test_add_fname(
    TFun func,
    const char *funcname)
{
    struct Test *current_test;

    SFZUTF_ASSERT(sfzutf_current_tcase != NULL);
    current_test = sfzutf_AssertNotNull(SFZUTF_CALLOC(sizeof(struct Test), 1));
    current_test->Name_p = funcname;
    current_test->TestFunc = func;
    NodeAdd((struct TestList *) &(sfzutf_current_tcase->TestList_p), current_test);
}

void
sfzutf_loop_test_add_fname(
    TFun func,
    const char *funcname,
    int mi,
    int ma)
{
    struct Test *current_test;

    SFZUTF_ASSERT(sfzutf_current_tcase != NULL);
    current_test = sfzutf_AssertNotNull(SFZUTF_CALLOC(sizeof(struct Test), 1));
    current_test->Name_p = funcname;
    current_test->TestFunc = func;
    current_test->Start = mi;
    current_test->EndPlus1 = ma;
    NodeAdd((struct TestList *) &(sfzutf_current_tcase->TestList_p), current_test);
}

void
sfzutf_tcase_add_fixture(
    SFun start,
    SFun end)
{
    struct Fixture *current_fixture;

    SFZUTF_ASSERT(sfzutf_current_tcase != NULL);
    if (sfzutf_current_tcase->FixtureList_p)
    {
        /* avoid duplicate fixture */
        if (sfzutf_current_tcase->FixtureList_p->StartFunc == start &&
            sfzutf_current_tcase->FixtureList_p->EndFunc == end)
        {
            return;
        }
    }
    current_fixture = sfzutf_AssertNotNull(SFZUTF_CALLOC(sizeof(struct Fixture), 1));
    current_fixture->Name_p = "fixture";
    current_fixture->StartFunc = start;
    current_fixture->EndFunc = end;
    NodeAdd((struct TestList *) &(sfzutf_current_tcase->FixtureList_p), current_fixture);
}


int
sfzutf_run_fixtures_and_test(
    struct Test *Test_p,
    struct Fixture *Fixture_p,
    int Count)
{
    int res = 0;

    if (Fixture_p != NULL)
    {
        if (Fixture_p->StartFunc != NULL)
        {
            Fixture_p->StartFunc();
        }

        res = sfzutf_run_fixtures_and_test(Test_p, Fixture_p->NextFixture_p, Count);

        if (Fixture_p->EndFunc != NULL)
        {
            Fixture_p->EndFunc();
        }
    }
    else
    {
        sfzutf_utils_event(SFZUTF_EVENT_TEST_BEGIN,
            Test_p->Name_p, Test_p);

        if (Test_p->TestFunc != NULL)
        {
            Test_p->TestFunc(Count);
        }

        sfzutf_utils_event(SFZUTF_EVENT_TEST_END,
            Test_p->Name_p, Test_p);
    }

    return res;
}

int
sfzutf_run_tcases(
    struct TestCase *TestCase_p)
{
    int Failures = 0;
    int Count;
    struct Test *Test_p;
    struct Fixture *Fixture_p;

    while (TestCase_p != NULL)
    {
        if (TestCase_p->Enabled)
        {
            L_TESTLOG(LF_TESTCASE_BEGIN, "%s", TestCase_p->Name_p);

            sfzutf_utils_event(SFZUTF_EVENT_TCASE_BEGIN,
                TestCase_p->Name_p, TestCase_p);

            Test_p = TestCase_p->TestList_p;
            Fixture_p = TestCase_p->FixtureList_p;

            while (Test_p != NULL)
            {
                if (Test_p->Enabled)
                {
                    if (Test_p->Start == 0 && Test_p->EndPlus1 == 0)
                    {
                        L_TESTLOG(LF_TEST_BEGIN, "%s", Test_p->Name_p);
                        Failures += sfzutf_run_fixtures_and_test(Test_p,
                            Fixture_p, 0);
                        L_TESTLOG(LF_TEST_END, "%s", Test_p->Name_p);
                    }
                    else
                    {
                        for (Count = Test_p->Start;
                             Count < Test_p->EndPlus1; Count++)
                        {
                            L_TESTLOG(LF_TEST_BEGIN, "%s:%d", Test_p->Name_p, Count);
                            Failures += sfzutf_run_fixtures_and_test(
                                Test_p,
                                Fixture_p,
                                Count);
                            L_TESTLOG(LF_TEST_END, "%s:%d", Test_p->Name_p, Count);
                        } /* for */
                    }
                }
                Test_p = Test_p->NextTest_p;
            }

            sfzutf_utils_event(SFZUTF_EVENT_TCASE_END,
                TestCase_p->Name_p, TestCase_p);

            L_TESTLOG(LF_TESTCASE_END, "%s", TestCase_p->Name_p);
        }

        TestCase_p = TestCase_p->NextCase_p;
    } /* while */

    return Failures;
}

int
sfzutf_run_suite(
    struct TestSuite *TestSuite_p)
{
    int Failures = 0;
    struct TestCase *TestCase_p;

    TestCase_p = TestSuite_p->TestCaseList_p;

    while (TestSuite_p)
    {
        if (TestSuite_p->Enabled)
        {
            int NewFailures;

            L_TESTLOG(LF_SUITE_BEGIN, "%s", TestSuite_p->Name_p);

            sfzutf_utils_event(SFZUTF_EVENT_SUITE_BEGIN,
                TestSuite_p->Name_p, TestSuite_p);

            NewFailures = sfzutf_run_tcases(TestCase_p);

            if (NewFailures == 0)
            {
                L_TESTLOG(LF_SUITE_END, "%s (SUCCESS)", TestSuite_p->Name_p);
            }
            else
            {
                L_TESTLOG(LF_SUITE_END, "%s (%d failed)",
                    TestSuite_p->Name_p,
                    NewFailures);
            }

            Failures += NewFailures;

            sfzutf_utils_event(SFZUTF_EVENT_SUITE_END,
                TestSuite_p->Name_p, TestSuite_p);
        }

        TestSuite_p = TestSuite_p->NextSuite_p;
    } /* while */

    return Failures;
}


bool
sfzutf_enable_tcases(
    struct TestCase *TestCase_p,
    const char * const TCaseName_p,
    const char * const TestName_p,
    const int * const IterValue_p,
    SfzUtfEnable_t *EnableMode_p)
{
    bool EnabledAny = false;
    bool EnabledAnyAtAll = false;
    struct Test *Test_p;

    /* struct Fixture *Fixture_p; */

    while (TestCase_p != NULL)
    {
        /* Select TestCase matching the conditions. */
        if (TCaseName_p == NULL ||
            SFZUTF_STREQ(TCaseName_p, TestCase_p->Name_p) ||
            *EnableMode_p == SFZUTF_ENABLE_ALL)
        {
            Test_p = TestCase_p->TestList_p;
            /* Fixture_p = TestCase_p->FixtureList_p; */

            while (Test_p != NULL)
            {
                /* Select  */
                if (TestName_p == NULL ||
                    SFZUTF_STREQ(TestName_p, Test_p->Name_p) ||
                    *EnableMode_p == SFZUTF_ENABLE_ALL)
                {
                    if (IterValue_p != NULL)
                    {
                        if (*EnableMode_p == SFZUTF_ENABLE_AFTER)
                        {
                            /* If IterValue is set and SFZUTF_ENABLE_AFTER
                               mode, trim test range according to IterValue. */
                            if (*IterValue_p < Test_p->Start)
                            {
                                /* Too small iter value, enable whole test. */
                                *EnableMode_p = SFZUTF_ENABLE_ALL;
                            }
                            else if (*IterValue_p + 1 < Test_p->EndPlus1)
                            {
                                Test_p->Start = *IterValue_p + 1;
                                *EnableMode_p = SFZUTF_ENABLE_ALL;
                            }
                            else
                            {
                                /* Value beyond range => skip test. */
                            }
                        }
                        else if (*EnableMode_p == SFZUTF_ENABLE_SINGLE)
                        {
                            if (*IterValue_p >= Test_p->Start &&
                                *IterValue_p < Test_p->EndPlus1)
                            {
                                /* Enable single iteration. */
                                Test_p->Start = *IterValue_p;
                                Test_p->EndPlus1 = *IterValue_p + 1;
                            }
                            else
                            {
                                /* Out of range, skip this test */
                                goto skipEnable;
                            }
                        }
                    }

                    if (*EnableMode_p == SFZUTF_ENABLE_SINGLE ||
                        *EnableMode_p == SFZUTF_ENABLE_ALL)
                    {
                        Test_p->Enabled = true;
                        EnabledAny = true;
                    }
                    else if (*EnableMode_p == SFZUTF_ENABLE_AFTER)
                    {
                        if (TestName_p != NULL)
                        {
                            *EnableMode_p = SFZUTF_ENABLE_ALL;
                        }
                    }
                }
skipEnable:
                Test_p = Test_p->NextTest_p;
            } /* while */

            /* If enable after mode has been chosen. */
            if (TestName_p == NULL &&
                *EnableMode_p == SFZUTF_ENABLE_AFTER)
            {
                *EnableMode_p = SFZUTF_ENABLE_ALL;
            }
        }

        if (EnabledAny)
        {
            TestCase_p->Enabled = true;
            EnabledAnyAtAll = true;
            if (*EnableMode_p == SFZUTF_ENABLE_SINGLE)
            {
                EnabledAny = false;
            }
        }
        TestCase_p = TestCase_p->NextCase_p;
    } /* while */

    return EnabledAnyAtAll;
}

bool
sfzutf_enable_suite(
    struct TestSuite *TestSuite_p,
    const char * const SuiteName_p,
    const char * const TCaseName_p,
    const char * const TestName_p,
    const int * const IterValue_p,
    const SfzUtfEnable_t OrigEnableMode)
{
    bool EnabledAny = false;
    struct TestCase *TestCase_p;
    SfzUtfEnable_t EnableModeStorage = OrigEnableMode;
    SfzUtfEnable_t *EnableMode_p = &EnableModeStorage;

    TestCase_p = TestSuite_p->TestCaseList_p;

    /* Select Suite matching the conditions. */
    if (SuiteName_p == NULL ||
        SFZUTF_STREQ(SuiteName_p, TestSuite_p->Name_p) ||
        *EnableMode_p == SFZUTF_ENABLE_ALL)
    {
        EnabledAny = sfzutf_enable_tcases(TestCase_p,
            TCaseName_p,
            TestName_p,
            IterValue_p,
            EnableMode_p);
        if (EnabledAny)
        {
            TestSuite_p->Enabled = true;
        }

        if (TestCase_p == NULL &&
            *EnableMode_p == SFZUTF_ENABLE_AFTER)
        {
            *EnableMode_p = SFZUTF_ENABLE_ALL;
        }
    }

    if (TestSuite_p->NextSuite_p)
    {
        EnabledAny |= sfzutf_enable_suite(TestSuite_p->NextSuite_p,
            SuiteName_p,
            TCaseName_p,
            TestName_p,
            IterValue_p,
            *EnableMode_p);
    }

    return EnabledAny;
}


void
sfzutf_disable_all(
    struct TestSuite *TestSuite_p)
{
    while (TestSuite_p)
    {
        struct TestCase *TestCase_p = TestSuite_p->TestCaseList_p;

        while (TestCase_p)
        {
            struct Test *Test_p = TestCase_p->TestList_p;

            while (Test_p)
            {
                Test_p->Enabled = false;
                Test_p = Test_p->NextTest_p;
            } /* while */

            TestCase_p->Enabled = false;
            TestCase_p = TestCase_p->NextCase_p;
        } /* while */

        TestSuite_p->Enabled = false;
        TestSuite_p = TestSuite_p->NextSuite_p;
    } /* while */
}


/* end of file sfzutf.c */
