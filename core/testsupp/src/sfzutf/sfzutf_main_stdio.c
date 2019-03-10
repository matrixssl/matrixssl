/* sfzutf_main_stdio.c
 *
 * Description: SFZUTF implementation file that provides application main()
 *              and parses the command line parameters.
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

#include "osdep_stdio.h"
#include "osdep_errno.h"
#include "osdep_stdlib.h"         /* For atoi(). */

#include "sfzutf_internal.h"

#include "implementation_defs.h"

#ifdef WIN32
# include <conio.h>

static int
sfzutf_main_win32_getinput(
    char * const c_p)
{
    int c = _getch();

    /* handle ctrl+c here */
    if (c == 3)
    {
        return -3;
    }

    if (c_p)
    {
        *c_p = (char) c;
        return 1;   /* returned input */
    }

    return 0;       /* returned nothing */
}

#endif /* WIN32 */

#ifdef linux
# include "osdep_stdio.h"
# include <termios.h>
# include "osdep_unistd.h"

static int
sfzutf_main_linux_getinput(
    char * const c_p)
{
    int c = getchar();

    /* handle ctrl+c here */
    if (c == 3)
    {
        return -3;
    }

    if (c == 10)
    {
        c = 13;             /* enter */
    }
    if (c == 127)
    {
        c = 8;              /* backspace */

    }
    if (c_p)
    {
        *c_p = (char) c;
        return 1;   /* returned input */
    }

    return 0;       /* returned nothing */
}

#endif /* linux */

static void
PrintTestList(void)
{
    struct TestNode *p = (struct TestNode *) sfzutf_current_suite->TestCaseList_p;

    Fprintf(stderr,
        "Suite %s:\n",
        sfzutf_current_suite->Name_p);

    while (p)
    {
        struct Test *T_p = ((struct TestCase *) p)->TestList_p;

        Fprintf(stderr,
            "  TestCase: %s\n",
            p->NodeName_p);

        while (T_p)
        {
            Fprintf(stderr,
                "   Test: %s\n", T_p->Name_p);
            T_p = T_p->NextTest_p;
        }

        p = p->NextNode_p;
    }
}


/* Handle arguments for test runner. */
const char *
stfutf_args(
    int argc,
    const char *argv[],
    const char **pp_suite_id,
    const char **pp_tcase_id,
    const char **pp_test_id,
    const char **pp_iter_id,
    SfzUtfEnable_t *p_enable_mode)
{
    int argp = 1;

    while (argp < argc)
    {
        const char *p_arg = argv[argp];
        if (streq_lit_prefix(p_arg, "--suite="))
        {
            if (*pp_suite_id == NULL)
            {
                *pp_suite_id = p_arg + strlen_lit("--suite=");
            }
            else
            {
                return "Option --suite specified twice.";
            }
        }
        else if (streq_lit(p_arg, "--suite"))
        {
            return "Option --suite=name requires parameter.";
        }
        else if (streq_lit_prefix(p_arg, "--tcase="))
        {
            if (*pp_tcase_id == NULL)
            {
                *pp_tcase_id = p_arg + strlen_lit("--tcase=");
            }
            else
            {
                return "Option --tcase specified twice.";
            }
        }
        else if (streq_lit(p_arg, "--tcase"))
        {
            return "Option --tcase=name requires parameter.";
        }
        else if (streq_lit_prefix(p_arg, "--test="))
        {
            if (*pp_test_id == NULL)
            {
                *pp_test_id = p_arg + strlen_lit("--test=");
            }
            else
            {
                return "Option --test specified twice.";
            }
        }
        else if (streq_lit(p_arg, "--test"))
        {
            return "Option --test=name requires parameter.";
        }
        else if (streq_lit_prefix(p_arg, "--iter="))
        {
            if (*pp_iter_id == NULL)
            {
                *pp_iter_id = p_arg + strlen_lit("--iter=");
            }
            else
            {
                return "Option --iter specified twice.";
            }
        }
        else if (streq_lit(p_arg, "--iter"))
        {
            return "Option --iter=value requires parameter.";
        }
        else if (streq_lit(p_arg, "--only"))
        {
            if (*p_enable_mode == SFZUTF_ENABLE_UNDETERMINED)
            {
                *p_enable_mode = SFZUTF_ENABLE_SINGLE;
            }
            else if (*p_enable_mode == SFZUTF_ENABLE_SINGLE)
            {
                return "Option --only specified twice.";
            }
            else
            {
                return "Options --after and --only are mutually incompatible.";
            }
        }
        else if (streq_lit(p_arg, "--after"))
        {
            if (*p_enable_mode == SFZUTF_ENABLE_UNDETERMINED)
            {
                *p_enable_mode = SFZUTF_ENABLE_AFTER;
            }
            else if (*p_enable_mode == SFZUTF_ENABLE_AFTER)
            {
                return "Option --after specified twice.";
            }
            else
            {
                return "Options --after and --only are mutually incompatible.";
            }
        }
#ifndef SFZUTF_REMOVE_INTERACTIVE_MODE
        else if (streq_lit(p_arg, "--int"))
        {
# ifdef WIN32
            sfzutf_interactive_start(
                sfzutf_main_win32_getinput);
# endif
# ifdef linux
            struct termios oldt, newt;
            tcgetattr( STDIN_FILENO, &oldt );
            newt = oldt;
            newt.c_lflag &= ~( ICANON | ECHO );
            tcsetattr( STDIN_FILENO, TCSANOW, &newt );
            sfzutf_interactive_start(
                sfzutf_main_linux_getinput);
            tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
# endif
            exit(0);
        }
#endif
        else if (streq_lit(p_arg, "--help"))
        {
            Fprintf(stderr,
                "Accepted options: \n"
                "Usage:          --help               "
                "display this message and exit\n"
                "                --int                "
                "start in interactive mode\n"
                "                --suite=name         "
                "run only/after specified test suite\n"
                "                --tcase=name         "
                "run only/after specified test case\n"
                "                --test=name          "
                "run only/after specified test\n"
                "                --list               "
                "list available test cases\n"
                "                --iter=value         "
                "run only/after specified test iteration\n"
                "                --only               "
                "run only specific test (default)\n"
                "                --after              "
                "run only tests *after* specific test\n");
            exit(0);
        }
        else if (streq_lit(p_arg, "--list"))
        {
            PrintTestList();
            /* Exit immediately after listing. */
            exit(0);
        }
        else if (streq_lit_prefix(p_arg, "-"))
        {
            return "Unrecognized option.";
        }
        else
        {
            return "Invalid arguments.";
        }

        argp++;
    }
    return NULL;
}


#define SFZUTF_FILE_MAX_ARGS 16
#define SFZUTF_FILE_MAX_ARGLEN 128

static char *
file_readLine(FILE *File_p)
{
    char stringStorage[SFZUTF_FILE_MAX_ARGLEN];
    char *string_p;
    uint32_t len;

    string_p = fgets(stringStorage, SFZUTF_FILE_MAX_ARGLEN, File_p);

    if (string_p == NULL)
    {
        /* errno is already set. */
        return NULL;
    }

    len = SFZUTF_STRLEN(string_p);
    string_p = SFZUTF_MALLOC(len);
    if (string_p == NULL)
    {
        errno = ENOMEM; /* Set errno ourselves. */
        return NULL;
    }

    SFZUTF_MEMCPY(string_p, stringStorage, len);
    return string_p;
}

static char *
line_chomp(char *line_p)
{
    char *origLine_p = line_p;
    char *char_p = line_p;
    char ch;

    if (char_p == NULL)
    {
        return NULL;
    }

    while ((ch = *char_p) != 0)
    {
        if (ch == 10)
        {
            if (char_p[1] == 0)
            {
                char_p[0] = 0;
            }
        }
        char_p++;
    }

    return origLine_p;
}

static char *
line_skipHorizontalWhiteSpace(const char *line_p)
{
    const char *char_p = line_p;
    char ch;

    if (char_p == NULL)
    {
        return NULL;
    }

    /* Skip horizontal white space characters and one extra character.
       Currently handles space, tab and backspace. */
    do
    {
        ch = *(char_p++);
    }
    while (ch == ' ' || ch == 9 || ch == 8);

    /* Return to character that was not horizontal white space. */
    char_p--;

    /* Notice: This cast is similar to the ones in str*** functions. */
    return (char *) char_p;
}

/* Type for argv argument vector. */
typedef const char **argv_t;

static const char *
file_readArgs(
    FILE *File_p,
    int *Argc_p,
    argv_t * const Argv_p)
{
    int newArgc = 0;
    argv_t newArgv;
    const char *error_p = NULL;
    char *line_p = NULL;

    newArgv = SFZUTF_CALLOC(sizeof(const char *), SFZUTF_FILE_MAX_ARGS);

    if (newArgv != NULL)
    {
        /* Got space for newArgv. */

        while ((line_p = file_readLine(File_p)) != NULL)
        {
            char *line_start_p = line_p;
            line_start_p = line_skipHorizontalWhiteSpace(line_p);
            if (line_start_p == NULL ||
                *line_start_p == '\0' ||
                *line_start_p == '\n' ||
                *line_start_p == '#')
            {
                /* Skip empty lines and comment lines. */
                SFZUTF_FREE(line_p);
            }
            else
            {
                if (newArgc >= SFZUTF_FILE_MAX_ARGS)
                {
                    error_p = "Too many arguments";
                    SFZUTF_FREE(line_p);
                    SFZUTF_FREE(newArgv);
                    return error_p;
                }

                line_chomp(line_start_p);
                newArgv[newArgc] = line_start_p;
                newArgc++;
            }
        }
    }
    else
    {
        /* No memory => exit with error. */
        error_p = "Not enough memory for argument vector";
    }

    *Argc_p = newArgc;
    *Argv_p = newArgv;

    return error_p;
}


/* Main program for tests. */
int main(int argc, argv_t argv)
{
    int number_failed;
    bool EnabledAnyTests;
    int retcode = 1;
    const char *Error_p;
    const char *SuiteName_p = NULL;
    const char *TCaseName_p = NULL;
    const char *TestName_p = NULL;
    const char *IterString_p = NULL;
    int IterValue;
    bool IterValueSet;

    SfzUtfEnable_t EnableMode = SFZUTF_ENABLE_UNDETERMINED;

    build_suite();

    sfzutf_tcase_finish();

    if (argc == 0)
    {
        int i;

        L_TESTLOG(LF_GLOBAL_NOTICE,
            "Did not get command line arguments.");
        L_TESTLOG(LF_GLOBAL_NOTICE,
            "Attempting to read arguments from stdin.");

        Error_p = file_readArgs(stdin, &argc, &argv);
        if (Error_p)
        {
            L_TESTLOG(LF_GLOBAL_ERROR, "*** Argument reading failed: %s", Error_p);
            return retcode;
        }

        if (argc <= 0)
        {
            L_TESTLOG(LF_GLOBAL_ERROR, "*** Too few arguments from stdin, "
                "expected at least command name");
            return retcode;
        }

        for (i = 0; i < argc; i++)
        {
            L_TESTLOG(LFG_GLOBAL_NOTICE, "Arg[%d]: %s\n", i, argv[i]);
        }
    }

    Error_p = stfutf_args(
        argc, argv,
        &SuiteName_p,
        &TCaseName_p,
        &TestName_p,
        &IterString_p,
        &EnableMode);

    IterValueSet = IterString_p != NULL;
    if (IterValueSet)
    {
        IterValue = atoi(IterString_p);
    }

    if (Error_p != NULL)
    {
        L_TESTLOG(LF_GLOBAL_ERROR, "*** Argument parsing failed: %s", Error_p);
        return retcode;
    }

    if (EnableMode == SFZUTF_ENABLE_UNDETERMINED)
    {
        EnableMode = SFZUTF_ENABLE_SINGLE;
    }

    EnabledAnyTests = sfzutf_enable_suite(sfzutf_current_suite,
        SuiteName_p,
        TCaseName_p,
        TestName_p,
        IterValueSet ? &IterValue : NULL,
        EnableMode);

    if (EnableMode == SFZUTF_ENABLE_SINGLE && EnabledAnyTests == false)
    {
        L_TESTLOG(LF_GLOBAL_ERROR, "*** No tests enabled.");
        return retcode;
    }

    sfzutf_utils_event(SFZUTF_EVENT_BEGIN, "(GLOBAL)", sfzutf_current_suite);

    number_failed = sfzutf_run_suite(sfzutf_current_suite);

    sfzutf_utils_event(SFZUTF_EVENT_END, "(GLOBAL)", sfzutf_current_suite);

    if (number_failed == 0)
    {
        retcode = 0;
        L_TESTLOG(LF_GLOBAL_SUCCESS, "*** All tests executed successfully.");
    }
    else
    {
        if (number_failed < 0)
        {
            L_TESTLOG(LF_GLOBAL_ERROR, "*** Error running test runner.");
        }
        else
        {
            L_TESTLOG(LF_GLOBAL_FAILURE, "*** %d failed tests", number_failed);
        }
    }

    return retcode;
}

/* end of file sfzutf_main_stdio.c */
