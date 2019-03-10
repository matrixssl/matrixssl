/* sfzutf_interactive.c
 *
 * Description: SFZUTF Interactive Mode.
 */

/*****************************************************************************
* Copyright (c) 2016-2018 INSIDE Secure Oy. All Rights Reserved.
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

#include "implementation_defs.h"
#include "sfzutf_internal.h" /* API to implement */

#include "osdep_ctype.h"           /* toupper */
#include "osdep_stdio.h"           /* Printf */

static struct
{
    int SelectionLevel; /* 0 = top, 1 = selected testcase, 2 = selected test */
    int SelectionBlock; /* 0, 1, 2, etc. */

    struct TestCase *Selected_TestCase_p;
    char Selected_TestCase_Letter;

    struct Test *Selected_Test_p;
    char Selected_Test_Letter;

} SFZUTF_Interactive;

#define SFZUTF_BLOCKS_MAX 10

static void
SFZUTF_Interactive_PrintPrompt(void)
{
    char Prompt[SFZUTF_BLOCKS_MAX + 1 /*test case*/ + 1 /*test*/ + 1 /*nul*/];
    int i;

    for (i = 0; i < SFZUTF_Interactive.SelectionBlock; i++)
    {
        Prompt[i] = ']';
    }
    Prompt[i] = 0;

    if (SFZUTF_Interactive.SelectionLevel > 0)
    {
        /* tcase selected */
        Prompt[i++] = SFZUTF_Interactive.Selected_TestCase_Letter;
        Prompt[i] = 0;

        if (SFZUTF_Interactive.SelectionLevel > 1)
        {
            /* test selected */
            Prompt[i++] = SFZUTF_Interactive.Selected_Test_Letter;
            Prompt[i] = 0;
        }
    }

    Printf("\n" "sfzutf %s>\n", Prompt);
}

static void
SFZUTF_Interactive_PrintHelp(void)
{
    Printf(
        "Help:\n"
        "  ?        Show help\n"
        "  <ctrl+c> Exit\n"
        "  <enter>  Show prompt\n"
        "  <space>  List options\n"
        "  <bs>     Up one level\n"
        "  \\        To top level\n"
        "  A..Z     Select option\n"
        "  ]        Next block of options\n"
        "  .        Execute\n"
        "  +        Execute + following\n");
}

static void
SFZUTF_Interactive_PrintList(void)
{
    int SkipBlocks = SFZUTF_Interactive.SelectionBlock * 26;
    struct TestCase *TC_p;
    struct Test *T_p;
    char C = 'A';

    switch (SFZUTF_Interactive.SelectionLevel)
    {
    case 0:
        /* selected nothing: show tcases */

        Printf("Test Suite: '%s'\n",
               sfzutf_current_suite->Name_p);

        Printf("\nPossible Test Cases:\n");

        TC_p = sfzutf_current_suite->TestCaseList_p;
        while (TC_p)
        {
            if (SkipBlocks > 0)
            {
                SkipBlocks--;
            }
            else
            {
                Printf(" %c : %s\n",
                    C,
                    TC_p->Name_p);
                C++;

                if (C > 'Z')
                {
                    Printf("\nMore options in next block (use ])\n");
                    break;
                }
            }
            TC_p = TC_p->NextCase_p;
        }     /* while */

        break;

    case 1:
        /* selected tcase: show tests */
        Printf("Test Suite: '%s'\n",
               sfzutf_current_suite->Name_p);

        Printf(" Test Case: '%s'\n",
               SFZUTF_Interactive.Selected_TestCase_p->Name_p);

        Printf("\nPossible Tests:\n");

        T_p = SFZUTF_Interactive.Selected_TestCase_p->TestList_p;
        while (T_p)
        {
            Printf(" %c : %s\n", C, T_p->Name_p);
            T_p = T_p->NextTest_p;
            C++;

            if (C > 'Z')
            {
                Printf("\nToo many options! (hint: split test case)\n");
                break;
            }
        }     /* while */

        break;

    case 2:
        /* selected test: just show the test name */
        Printf("Test Suite: '%s'\n", sfzutf_current_suite->Name_p);
        Printf(" Test Case: '%s'\n",
               SFZUTF_Interactive.Selected_TestCase_p->Name_p);
        Printf("      Test: '%s'\n",
               SFZUTF_Interactive.Selected_Test_p->Name_p);

        break;

    default:
        L_DEBUG(
            LF_SFZUTF,
            "Unexpected SelectionLevel=%d\n",
            SFZUTF_Interactive.SelectionLevel);
        return;
    } /* switch */
}

static int
SFZUTF_Interactive_MakeSelection(
    char C_wanted)         /* A..Z */
{
    int SkipBlocks = SFZUTF_Interactive.SelectionBlock * 26;
    struct TestCase *TC_p;
    struct Test *T_p;
    char C = 'A';

    switch (SFZUTF_Interactive.SelectionLevel)
    {
    case 0:
        /* select tcase */
        TC_p = sfzutf_current_suite->TestCaseList_p;
        while (TC_p)
        {
            if (SkipBlocks > 0)
            {
                SkipBlocks--;
            }
            else
            {
                if (C == C_wanted)
                {
                    SFZUTF_Interactive.Selected_TestCase_Letter = C;
                    SFZUTF_Interactive.Selected_TestCase_p = TC_p;
                    SFZUTF_Interactive.SelectionLevel = 1;
                    return 0;
                }

                C++;
                if (C > 'Z')
                {
                    break;
                }
            }

            TC_p = TC_p->NextCase_p;
        }     /* while */
        break;

    case 1:
        /* select test */
        T_p = SFZUTF_Interactive.Selected_TestCase_p->TestList_p;
        while (T_p)
        {
            if (C == C_wanted)
            {
                SFZUTF_Interactive.Selected_Test_Letter = C;
                SFZUTF_Interactive.Selected_Test_p = T_p;
                SFZUTF_Interactive.SelectionLevel = 2;
                return 0;
            }
            T_p = T_p->NextTest_p;
            C++;
            if (C > 'Z')
            {
                break;
            }
        }     /* while */
        break;

    default:
        break;
    } /* switch */

    /* invalid choice */
    /* or not possible to make a selection at this level */
    return -2;
}

static void
SFZUTF_Interactive_Execute(
    bool fPlusFollowing)
{
    SfzUtfEnable_t EnableMode;

    if (fPlusFollowing)
    {
        EnableMode = SFZUTF_ENABLE_AFTER;
    }
    else
    {
        EnableMode = SFZUTF_ENABLE_SINGLE;
    }

    sfzutf_disable_all(sfzutf_current_suite);

    switch (SFZUTF_Interactive.SelectionLevel)
    {
    case 0:
        /* run the test suite */
        sfzutf_enable_suite(
            sfzutf_current_suite,
            /*TestSuiteName:*/ NULL,
            /*TestCaseName:*/ NULL,
            /*TestName:*/ NULL,
            /*IterValue:*/ NULL,
            EnableMode);
        break;

    case 1:
        /* run the selected test case */
        sfzutf_enable_suite(
            sfzutf_current_suite,
            /*TestSuiteName:*/ NULL,
            /*TestCaseName:*/ SFZUTF_Interactive.Selected_TestCase_p->Name_p,
            /*TestName:*/ NULL,
            /*IterValue:*/ NULL,
            EnableMode);
        if (fPlusFollowing)
        {
            SFZUTF_Interactive.Selected_TestCase_p->Enabled = true;
        }
        break;

    case 2:
        /* run the selected test */
        sfzutf_enable_suite(
            sfzutf_current_suite,
            /*TestSuiteName:*/ NULL,
            /*TestCaseName:*/ NULL,
            /*TestName:*/ SFZUTF_Interactive.Selected_Test_p->Name_p,
            /*IterValue:*/ NULL,
            EnableMode);
        if (fPlusFollowing)
        {
            SFZUTF_Interactive.Selected_Test_p->Enabled = true;
        }
        break;

    default:
        return;

    } /* switch */

    /* the test cases to run have been selected */
    {
        int number_failed;

        sfzutf_utils_event(SFZUTF_EVENT_BEGIN, "(GLOBAL)", sfzutf_current_suite);

        number_failed = sfzutf_run_suite(sfzutf_current_suite);

        sfzutf_utils_event(SFZUTF_EVENT_END, "(GLOBAL)", sfzutf_current_suite);

        if (number_failed == 0)
        {
            L_TESTLOG(LF_GLOBAL_SUCCESS, "*** All tests executed successfully.");
            return;
        }

        if (number_failed < 0)
        {
            L_TESTLOG(LF_GLOBAL_ERROR, "*** Error running test runner.");
            return;
        }

        L_TESTLOG(LF_GLOBAL_FAILURE, "*** %d failed tests", number_failed);
    }
}

/* this function start interactive mode */
/* getinputfunc() can return input (return value: 1=input, <0=error) */
void
sfzutf_interactive_start(
    int (*getinputfunc)(char * const c_p))
{
    int res = 0;

    SFZUTF_Interactive.SelectionLevel = 0;
    SFZUTF_Interactive.SelectionBlock = 0;

    /* print welcome message */
    Printf("\n"
           "Welcome to SFZUTF Interactive Mode\n"
           "(press ? for help)\n");

    /* print an initial prompt */
    SFZUTF_Interactive_PrintPrompt();

    while (res >= 0)
    {
        char c = 0;

        /* get input */
        res = getinputfunc(&c);
        if (res == 1)
        {
            /* L_DEBUG(LF_SFZUTF,"Got %d\n", c); */

            /* got some input! */
            switch (c)
            {
            case 0x0d:
                /* enter */
                /* do nothing; just print a new prompt */
                SFZUTF_Interactive_PrintPrompt();
                break;

            case 0x08:
                /* back-space */
                if (SFZUTF_Interactive.SelectionLevel > 0)
                {
                    SFZUTF_Interactive.SelectionLevel--;
                    SFZUTF_Interactive_PrintPrompt();
                }
                else
                {
                    /* already at top level */
                    if (SFZUTF_Interactive.SelectionBlock > 0)
                    {
                        SFZUTF_Interactive.SelectionBlock--;
                        SFZUTF_Interactive_PrintPrompt();
                    }
                }
                break;

            case '\\':
                /* back-slash: return to top-level */
                if (SFZUTF_Interactive.SelectionLevel > 0 ||
                    SFZUTF_Interactive.SelectionBlock > 0)
                {
                    SFZUTF_Interactive.SelectionLevel = 0;
                    SFZUTF_Interactive.SelectionBlock = 0;
                    SFZUTF_Interactive_PrintPrompt();
                }
                break;

            case ' ':
                /* space: list request */
                /* list the possible entries at this level */
                /* prefix with A..Z */
                SFZUTF_Interactive_PrintList();
                SFZUTF_Interactive_PrintPrompt();
                break;

            case '?':
                /* question mark: help request */
                SFZUTF_Interactive_PrintHelp();
                SFZUTF_Interactive_PrintPrompt();
                break;

            case '.':
                SFZUTF_Interactive_Execute(/*plus following:*/ false);
                SFZUTF_Interactive_PrintPrompt();
                break;

            case '+':
                SFZUTF_Interactive_Execute(/*plus following:*/ true);
                SFZUTF_Interactive_PrintPrompt();
                break;

            case ']':
                if (SFZUTF_Interactive.SelectionBlock < SFZUTF_BLOCKS_MAX - 1)
                {
                    SFZUTF_Interactive.SelectionBlock++;
                    SFZUTF_Interactive_PrintPrompt();
                }
                break;

            default:
            {
                char C = (char) Toupper(c);
                if (C >= 'A' && C <= 'Z')
                {
                    /* selection request */
                    int res_sel;
                    res_sel = SFZUTF_Interactive_MakeSelection(C);
                    if (res_sel < 0)
                    {
                        Printf("Invalid choice: %c\n", c);
                    }
                    SFZUTF_Interactive_PrintPrompt();
                }
                else
                {
                    /* silently ignore */
                }
            }
            } /* switch */

            /* update the prompt */
        }
    } /* while */

    Printf("SFZUTF Interactive Mode: Bye!\n");
}


/* end of file sfzutf_interactive.c */
