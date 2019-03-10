/* This program illustrates logging. */

/* Note: This program is intended to run with all logging messages on. */

#ifndef _h_PS_CORECONFIG
# ifdef MATRIX_CONFIGURATION_INCDIR_FIRST
#  include <coreConfig.h> /* Must be first included */
# else
#  include "coreConfig.h" /* Must be first included */
# endif
#endif /* _h_PS_CORECONFIG */

/* Override any possible disabled logging, except verbose.
   This is neccessary, because the program is dependent on
   messages working as expected.
   Note: Normally do this setting via "coreConfig.h" */
#undef PS_NO_LOGF_FATAL
#undef PS_NO_LOGF_ERROR
#undef PS_NO_LOGF_WARNING
#undef PS_NO_LOGF_INFO
#undef PS_NO_LOGF_DEBUG
#undef PS_NO_LOGF_TRACE
#undef PS_NO_LOGF_CALL_TRACE

/* Intentionally omit one message class to see those messages are
   never detected by hook functions.
   Note: Normally do this setting via "coreConfig.h" */
#ifndef PS_NO_LOGF_VERBOSE
#define PS_NO_LOGF_VERBOSE
#endif /* PS_NO_LOGF_VERBOSE */

#include "psLog.h"

#ifndef debugf
#define debugf(x, ...) PS_LOGF_DEBUG(UNIT, x ,##__VA_ARGS__ )
#endif
#ifndef tracef
#define tracef(x, ...) PS_LOGF_TRACE(UNIT, x ,##__VA_ARGS__ )
#endif

void helper(void)
{
    tracef("Helper function starts\n");
    tracef("Helper function finished\n");
}

#include "osdep_stdio.h"
#include "osdep_assert.h"

/* Combined count of seen logs (in hex).
   Note: Although kludgy, a single counter allows short comparison of all
   counts. */
unsigned long long Counts = 0x0;

int hooked_0(const char *level, const char *unit)
{
    if (level == psLogf_Log_CallTrace) Counts += 0x1;
    if (level == psLogf_Log_Trace) Counts += 0x10;
    if (level == psLogf_Log_Verbose) Counts += 0x100;
    if (level == psLogf_Log_Debug) Counts += 0x1000;
    if (level == psLogf_Log_Info) Counts += 0x10000;
    if (level == psLogf_Log_Warning) Counts += 0x100000;
    if (level == psLogf_Log_Error) Counts += 0x1000000;
    if (level == psLogf_Log_Fatal) Counts += 0x10000000;
    return 0;
}

int hooked_1(const char *level, const char *unit)
{
    if (level == psLogf_Log_CallTrace) Counts += 0x1;
    if (level == psLogf_Log_Trace) Counts += 0x10;
    if (level == psLogf_Log_Verbose) Counts += 0x100;
    if (level == psLogf_Log_Debug) Counts += 0x1000;
    if (level == psLogf_Log_Info) Counts += 0x10000;
    if (level == psLogf_Log_Warning) Counts += 0x100000;
    if (level == psLogf_Log_Error) Counts += 0x1000000;
    if (level == psLogf_Log_Fatal) Counts += 0x10000000;
    return 1;
}

#ifndef Vprintf
#define Vprintf vprintf /* osdep_stdio.h may not have wrapper for vprintf. */
#endif

int hooked_print_context(const char *level,
                         const char *unit,
                         const char *format_string,
                         va_list va)
{
    if (level == psLogf_Log_Trace)
    {
        /* Logging classes supported by the function.
           This function intentionally only supports trace. */
        Vprintf(format_string, va);
    }
    else
    {
        return 0;
    }
}

int hooked_print_no_context(const char *level,
                            const char *unit,
                            const char *format_string,
                            va_list va)
{
    if (level == psLogf_Log_Trace)
    {
        /* Logging classes supported by the function.
           This function intentionally only supports trace. */
        PS_LOGF_RAW_FMT(format_string, va); /* Omit context. */
        Vprintf(format_string, va);
    }
    else
    {
        return 0;
    }
}

int hooked(void)
{
    psLogfSetHookEnabledCheck(hooked_0);
    /* All logging is disabled: */
    tracef("Omitted trace1\n");
    tracef("Omitted trace2\n");
    debugf("Omitted debug1\n");
    Assert(Counts == 0x1020);
    /* Try all message types once. */
    PS_LOGF_CALL_TRACE(LOG, "calltrace (%d)", 0);
    PS_LOGF_TRACE(LOG, "trace (%d)", 1);
    PS_LOGF_VERBOSE(LOG, "verbose (%d)", 2);
    PS_LOGF_DEBUG(LOG, "debug (%d)", 3);
    PS_LOGF_INFO(LOG, "info (%d)", 4);
    PS_LOGF_WARNING(LOG, "warning (%d)", 5);
    PS_LOGF_ERROR(LOG, "error (%d)", 6);
    PS_LOGF_FATAL(LOG, "fatal (%d)", 7);
    Assert(Counts == 0x11112031);
    psLogfSetHookEnabledCheck(hooked_1);
    psLogfSetHookPrintf(hooked_print_context);
    /* All logging is enabled: */
#ifdef PS_NO_LOGF_FILELINE
    tracef("Log message with context (partial context due to %s)\n",
           "PS_NO_LOGF_FILELINE");
#else
    tracef("Log message with context (if available)\n");
    Printf("Note: Configuration #define %s will omit file+line.\n",
           "PS_NO_LOGF_FILELINE");
#endif
    psLogfSetHookPrintf(hooked_print_no_context);
    debugf("Log message that is filtered within printing function.\n");
    tracef("Log message without context\n");
    psLogfSetHookPrintf(hooked_print_context);
    tracef("Finished with hooking test (displayed as log message)\n");
    Assert(Counts == 0x11113061);
    return 0;
}

int main(int argc, char *argv[])
{
    /* Note: If you see the program printing nothing, try
       setting environment variables, eg. PS_ENABLE_LOG=1,
       Or try ltrace -e getenv ./log. */

    if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'f')
    {
        Printf("Illustrate hooks\n");
        return hooked();
    }

    Printf("This program demonstrates logging functions.\n");
    Printf("Normally you should see nothing as debug and trace\n");
    Printf("defaults blocked. However, if you enable debugging via\n");
    Printf("environment variables such as PS_ENABLE_LOG all the log will be\n");
    Printf("visible.\n");
    Printf("Alternative invocations: %s -f   - illustrate hooking\n", argv[0]);
    
    debugf("Program starts\n");
    helper();
    debugf("Program finished\n");
    return 0;
}
