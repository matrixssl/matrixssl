#define _POSIX_C_SOURCE 200112L
#include "../psLog.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef USE_MULTITHREADING
#include <pthread.h>
#endif /* USE_MULTITHREADING */

#ifdef USE_MULTITHREADING
static pthread_mutex_t out_file_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif /* USE_MULTITHREADING */

#define PS_LOGF_UNIT_MAX_LEN 64

/* Check if logging is on.  */

/* File handle to use for log output. */
FILE *psLogfGetFile(const char *level, const char *unit)
{
    static volatile FILE *out_file = NULL;
    FILE *file;
    const char *str;

    /* Note: implementation of this function may choose to use different
       file handles for different log levels or units. */
    (void)level;
    (void)unit;

    if (out_file == NULL)
    {
#ifdef USE_MULTITHREADING
        pthread_mutex_lock(&out_file_mutex);
#endif /* USE_MULTITHREADING */
    }

    file = (FILE *) out_file;
    if (file == NULL)
    {
        str = getenv("PS_LOG_FILE");
        if (str != NULL)
        {
            file = fopen(str, "w");
            if (!file)
            {
                fprintf(
                        stderr,
                        "%s: Unable to open file %s, %s.\n",
                        __func__,
                        str,
                        "producing log to standard output");
                file = stdout;
            }
        }
        else
        {
            str = getenv("PS_LOG_FILE_APPEND");
        }
        
        if (file == NULL && str != NULL)
        {
            file = fopen(str, "a");
            if (!file)
            {
                fprintf(
                        stderr,
                        "%s: Unable to open file %s, %s.\n",
                        __func__,
                        str,
                        "producing log to standard output");
                file = stdout;
            }
        }
        
        if (file == NULL)
        {
            /* Default: output to standard output. */
            file = stdout;
        }
    }

    if (file && file != stdout)
    {
        /* Turn off buffering to avoid log truncation at abnormal program termination. */
        setvbuf(file, NULL, _IONBF, 0);
    }

    out_file = file;
#ifdef USE_MULTITHREADING
    pthread_mutex_unlock(&out_file_mutex);
#endif /* USE_MULTITHREADING */
    return file;
}

/* Function called for fatal logs. */
int psLogfFatal(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Function called for error logs. */
int psLogfError(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Function called for warnings logs. */
int psLogfWarning(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Function called for informational logs. */
int psLogfInfo(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Function called for debugging logs. */
int psLogfDebug(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Function called for verbose debugging logs. */
int psLogfVerbose(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Function called for trace logs. */
int psLogfTrace(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Function called for function trace logs. */
int psLogfCallTrace(const char *level, const char *unit, const char *fmt, ...)
{
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = psLogVaCommon(level, unit, fmt, ap);
    va_end(ap);
    return res;
}

/* Different values for unsigned char */
#define PS_LOGF_UNDECIDED       0 /* The default value for psLogfEnableStatus_t. */
#define PS_LOGF_DISABLED        1
#define PS_LOGF_DISABLED_FORCE  2
#define PS_LOGF_ENABLED         3
#define PS_LOGF_ENABLED_FORCE   4
typedef unsigned char psLogfEnableStatus_t;

/* psLogf static variables: These variables cache information on default processing
   of logs in order to avoid too many getenv() function calls. */
static psLogfEnableStatus_t psLogfDefaultFlag;
static psLogfEnableStatus_t psLogfCached[1 + 1 + (int) PS_LOGF_FATAL];
static unsigned long long psLogfCachedDisable;
static unsigned long long psLogfCachedEnable;

/* Check if loggin is enabled or disabled from environment variables and compile time parameters.
   Once checked, the value is cached within a static variable. */
psLogfEnableStatus_t psLogfIsEnabledGlobal(void)
{
    psLogfEnableStatus_t flag;

    /* Check default logging state: enabled or disabled. */
    flag = psLogfDefaultFlag;
    if (flag == PS_LOGF_UNDECIDED)
    {
        int has_disable = !!getenv("PS_DISABLE_LOG");
        int has_enable = !!getenv("PS_ENABLE_LOG");
        if (has_disable && !has_enable)
        {
            flag = PS_LOGF_DISABLED;
        }
        else if (has_enable && !has_disable)
        {
            flag = PS_LOGF_ENABLED;
        }
        else
        {
            /* Use compile time variables to pick the default setting. */
#ifdef PS_LOGF_ENABLED_BY_DEFAULT
            flag = PS_LOGF_ENABLED;
#else
            flag = PS_LOGF_DISABLED;
#endif
        }
        /* Store the default setting. */
        psLogfDefaultFlag = flag;
    }

    /* The flag can only be eanbled or disabled, i.e. initial state not modified by level or module. */
    assert(flag == PS_LOGF_ENABLED || flag == PS_LOGF_DISABLED);

    return flag;
}

/* Check if specific log level is enabled from environment variables.
   Once checked, the value is cached within a static variable. */
static psLogfEnableStatus_t psLogfIsEnabledLevel(psLogfLevel_t level_i)
{
    psLogfEnableStatus_t flag;
    static const char *psLogfEnvDisabledStr[] =
    {
        "PS_DISABLE_LOG_UNKNOWN",
        "PS_DISABLE_LOG_CALL_TRACE",
        "PS_DISABLE_LOG_TRACE",
        "PS_DISABLE_LOG_VERBOSE",
        "PS_DISABLE_LOG_DEBUG",
        "PS_DISABLE_LOG_INFO",
        "PS_DISABLE_LOG_WARNING",
        "PS_DISABLE_LOG_ERROR",
        "PS_DISABLE_LOG_FATAL"
    };
    static const char *psLogfEnvEnabledStr[] =
    {
        "PS_ENABLE_LOG_UNKNOWN",
        "PS_ENABLE_LOG_CALL_TRACE",
        "PS_ENABLE_LOG_TRACE",
        "PS_ENABLE_LOG_VERBOSE",
        "PS_ENABLE_LOG_DEBUG",
        "PS_ENABLE_LOG_INFO",
        "PS_ENABLE_LOG_WARNING",
        "PS_ENABLE_LOG_ERROR",
        "PS_ENABLE_LOG_FATAL"
    };

    flag = psLogfIsEnabledGlobal();
    if (flag == PS_LOGF_ENABLED)
    {
        if (psLogfCached[(int) level_i] == PS_LOGF_UNDECIDED)
        {
            psLogfCached[(int) level_i] =
                getenv(psLogfEnvDisabledStr[(int) level_i]) ? PS_LOGF_DISABLED_FORCE : flag;
        }
        return psLogfCached[(int) level_i];
    }

    /* Default == disabled, check if log is enabled: */

    if (psLogfCached[(int) level_i] == PS_LOGF_UNDECIDED)
    {
        psLogfCached[(int) level_i] =
            getenv(psLogfEnvEnabledStr[(int) level_i]) ? PS_LOGF_ENABLED : flag;
    }

    return psLogfCached[(int) level_i];
}

/* Filter log messages by level */
static psLogfLevel_t psLogfParseLevelStr(const char *level)
{
    psLogfLevel_t level_i = PS_LOGF_UNKNOWN;

    /* level should be in format Log_... decode the string. */
    if (level && level[0] == 'L' && level[1] == 'o' && level[2] == 'g' && level[3] == '_')
    {
        switch(level[4])
        {
        case 'C':
            level_i = strcmp(level + 5, "allTrace") ? PS_LOGF_UNKNOWN : PS_LOGF_CALL_TRACE;
            break;
        case 'T':
            level_i = strcmp(level + 5, "race") ? PS_LOGF_UNKNOWN : PS_LOGF_TRACE;
            break;
        case 'V':
            level_i = strcmp(level + 5, "erbose") ? PS_LOGF_UNKNOWN : PS_LOGF_VERBOSE;
            break;
        case 'D':
            level_i = strcmp(level + 5, "ebug") ? PS_LOGF_UNKNOWN : PS_LOGF_DEBUG;
            break;
        case 'I':
            level_i = strcmp(level + 5, "nfo") ? PS_LOGF_UNKNOWN : PS_LOGF_INFO;
            break;
        case 'W':
            level_i = strcmp(level + 5, "arning") ? PS_LOGF_UNKNOWN : PS_LOGF_WARNING;
            break;
        case 'E':
            level_i = strcmp(level + 5, "rror") ? PS_LOGF_UNKNOWN : PS_LOGF_ERROR;
            break;
        case 'F':
            level_i = strcmp(level + 5, "atal") ? PS_LOGF_UNKNOWN : PS_LOGF_FATAL;
            break;
        }
    }
    return level_i;
}

/* Up-to 64 most common unit + level pairs can be mapped to identifier with this table. */
enum
{
    PS_LOGF_ID_PS_CORE_TRACE,
    PS_LOGF_ID_PS_CORE_ERROR,
    PS_LOGF_ID_PS_CRYPTO_TRACE,
    PS_LOGF_ID_PS_MATRIXSSL_TRACE,
    PS_LOGF_ID_PS_MATRIXSSL_HS_TRACE,
    PS_LOGF_ID_PS_DTLS_TRACE,
    PS_LOGF_ID_LOGTEST_TRACE
} psLogfBitMapping_t;

/* Select if log is going to be output, based on combination of level and unit.
   The level has been mapped into constant and overall per level enable/disable database has
   been consulted. */
static int psLogfIsEnabledThisLog(psLogfLevel_t level_i, psLogfEnableStatus_t levelSelect,
                                  const char *unit)
{
    /* The most common units used can be kept in cache for look-ups. */
    int bit = -1;
    
    psLogfEnableStatus_t select = levelSelect;
    char buf[PS_LOGF_UNIT_MAX_LEN + 20];

    assert(select != PS_LOGF_DISABLED_FORCE &&
           select != PS_LOGF_ENABLED_FORCE); /* This function shall not be called if log is
                                                already disabled. */

    if (strlen(unit) > PS_LOGF_UNIT_MAX_LEN)
    {
        /* Too long unit name: just use verdict based on level selection. */
        return select != PS_LOGF_DISABLED;
    }
    
    if (strcmp(unit, "PS_CORE") == 0)
    {
        /* These are compatibility for MatrixSSL configuration. */
        if (level_i == PS_LOGF_TRACE)
        {
            bit = (int) PS_LOGF_ID_PS_CORE_TRACE;
#ifdef USE_CORE_TRACE
            if (select == PS_LOGF_DISABLED)
            {
                select = PS_LOGF_ENABLED; /* Turn on log according to configuration. */
            }
#endif /* USE_CORE_TRACE */
        }
        if (level_i == PS_LOGF_ERROR)
        {
            bit = (int) PS_LOGF_ID_PS_CORE_ERROR;
#ifdef USE_CORE_ERROR
            if (select == PS_LOGF_DISABLED)
            {
                select = PS_LOGF_ENABLED; /* Turn on log according to configuration. */
            }
#endif /* USE_CORE_ERROR */
        }
    }
    else if (strcmp(unit, "PS_CRYPTO") == 0)
    {
        /* These are compatibility for MatrixSSL configuration. */
        if (level_i == PS_LOGF_TRACE)
        {
            bit = (int) PS_LOGF_ID_PS_CRYPTO_TRACE;
#ifdef USE_CRYPTO_TRACE
            if (select == PS_LOGF_DISABLED)
            {
                select = PS_LOGF_ENABLED; /* Turn on log according to configuration. */
            }
#endif /* USE_CRYPTO_TRACE */
        }
    }
    else if (strcmp(unit, "PS_MATRIXSSL") == 0)
    {
        /* These are compatibility for MatrixSSL configuration. */
        if (level_i == PS_LOGF_INFO)
        {
            bit = (int) PS_LOGF_ID_PS_MATRIXSSL_TRACE;
#ifdef USE_SSL_INFORMATIONAL_TRACE
            if (select == PS_LOGF_DISABLED)
            {
                select = PS_LOGF_ENABLED; /* Turn on log according to configuration. */
            }
#endif /* USE_SSL_INFORMATIONAL_TRACE */
        }
    }
    else if (strcmp(unit, "PS_MATRIXSSL_HS") == 0)
    {
        if (level_i == PS_LOGF_TRACE)
        {
            bit = (int) PS_LOGF_ID_PS_MATRIXSSL_HS_TRACE;
#ifdef USE_SSL_HANDSHAKE_MSG_TRACE
            if (select == PS_LOGF_DISABLED)
            {
                select = PS_LOGF_ENABLED; /* Turn on log according to configuration. */
            }
#endif /* USE_SSL_HANDSHAKE_MSG_TRACE */
        }
    }
    else if (strcmp(unit, "PS_DTLS") == 0)
    {
        if (level_i == PS_LOGF_TRACE)
        {
            bit = (int) PS_LOGF_ID_PS_DTLS_TRACE;
#ifdef USE_DTLS_DEBUG_TRACE
            if (select == PS_LOGF_DISABLED)
            {
                select = PS_LOGF_ENABLED; /* Turn on log according to configuration. */
            }
#endif /* USE_DTLS_DEBUG_TRACE */
        }
    }
    else if (strcmp(unit, "LOGTEST") == 0)
    {
        if (level_i == PS_LOGF_TRACE)
        {
            bit = (int) PS_LOGF_ID_LOGTEST_TRACE;
        }
    }

    if (bit > -1)
    {
        if ((psLogfCachedDisable & (1ULL << bit)) > 0ULL)
        {
            /* This has been disabled. */
            return 0; /* Do not print. */
        }

        if ((psLogfCachedEnable & (1ULL << bit)) > 0ULL)
        {
            /* This has been enabled. */
            return 1; /* Print. */
        }

        /* Enabling / disabling status has not been cached look up. */
    }
    
    if (select == PS_LOGF_ENABLED)
    {
        /* Default is enabled, check if we should disable. */
        snprintf(buf, sizeof(buf), "PS_DISABLE_%.*s", (int)PS_LOGF_UNIT_MAX_LEN, unit);
        select = getenv(buf) ? PS_LOGF_DISABLED : select;
    }
    else if (select == PS_LOGF_DISABLED)
    {
        /* Default is disable, check if we should enable. */
        snprintf(buf, sizeof(buf), "PS_ENABLE_%.*s", (int)PS_LOGF_UNIT_MAX_LEN, unit);
        select = getenv(buf) ? PS_LOGF_ENABLED : PS_LOGF_DISABLED;
    }

    if (bit > -1 && select == PS_LOGF_ENABLED)
    {
        psLogfCachedEnable = psLogfCachedEnable | (1ULL << bit);
    }
    
    if (bit > -1 && select == PS_LOGF_DISABLED)
    {
        psLogfCachedDisable = psLogfCachedDisable | (1ULL << bit);
    }
    
    return select != PS_LOGF_DISABLED;
}

/* Actual output function: This function is only called when log is to be output.
   This function may also be called with empty strings just to test if output would be produced. */
int psLogVaCommonOutput(FILE *out_file, const char *fmt, va_list args)
{
    (void)vfprintf(out_file, fmt, args);
    return 1;
}

static int (*pslogfenabledhook)(const char *level, const char *unit);

/* Set hook for checking if log type is enabled. */
psLogfSetHookEnabledCheckFunction_t psLogfSetHookEnabledCheck(
        psLogfSetHookEnabledCheckFunction_t hook)
{
    psLogfSetHookEnabledCheckFunction_t hook_old = pslogfenabledhook;
    pslogfenabledhook = hook;
    return hook_old;
}

static psLogfSetHookPrintfFunction_t pslogfprintfhook;

psLogfSetHookPrintfFunction_t psLogfSetHookPrintf(
        psLogfSetHookPrintfFunction_t hook)
{
    psLogfSetHookPrintfFunction_t hook_old = pslogfprintfhook;
    pslogfprintfhook = hook;
    return hook_old;
}

/* Common function for handling trace logs. */
int psLogVaCommon(const char *level, const char *unit, const char *fmt, va_list args)
{
    int res = 0;
    psLogfLevel_t level_i;
    psLogfEnableStatus_t levelSelect;
    int output_log;

    if (pslogfenabledhook)
    {
        output_log = pslogfenabledhook(level, unit);
        if (output_log >= 0)
        {
            /* 0 == do not print, 1 == print. */
            goto conditional_output_log;
        }
        /* < 0 (-1) == Query configuration variables. */
    }
    level_i = psLogfParseLevelStr(level);
    levelSelect = psLogfIsEnabledLevel(level_i);

    if (levelSelect != PS_LOGF_DISABLED_FORCE)
    {
        output_log = psLogfIsEnabledThisLog(level_i, levelSelect, unit);

        /* Now output_log is non-zero only if log should be printed. */
    conditional_output_log:

        if (output_log)
        {
            /* Detect is enabled request from its unique formatting string.
               Note: this check depends on value of PS_LOGF_FMT_IS_ENABLED
               macro. */
            if (fmt[0] == '%' && fmt[1] == '.' && fmt[2] == '0' &&
                fmt[3] == 's' && fmt[4] == 0)
            {
                return 1; /* The print request was just a probe. */
            }
            
            /* Perform default logging. */
            res = -1;

            if (pslogfprintfhook)
            {
                /* If there is hook for printing, let it replace res. */
                res = pslogfprintfhook(level, unit, fmt, args);
            }

            /* If res == -1 then we perform default logging function. */
            if (res == -1)
            {
                FILE *out_file;

                out_file = psLogfGetFile(level, unit);

                if (out_file)
                {
                    res = psLogVaCommonOutput(out_file, fmt, args);
                }
                else
                {
                    res = 0; /* No output file => consider call a failure. */
                }
            }
        }
    }
    return res;
}

void psLogfFlush(void)
{
    int i;

    /* Clear all cached log enabling/disabling information. */
    psLogfDefaultFlag = 0;
    for(i = 0; i <= 1 + (int) PS_LOGF_FATAL; i++)
    {
        psLogfCached[i] = 0;
    }
    psLogfCachedDisable = 0ULL;
    psLogfCachedEnable = 0ULL;
}

/* Enable logging for select levels or modules. */
void psLogfEnable(const char *module_or_level)
{
    char buf[PS_LOGF_UNIT_MAX_LEN + 20];

    if (strlen(module_or_level) <= PS_LOGF_UNIT_MAX_LEN)
    {
        /* use unsetenv/setenv to specify logging settings. */
        snprintf(buf, sizeof(buf), "PS_DISABLE_%.*s", (int)PS_LOGF_UNIT_MAX_LEN,
                 module_or_level);
        unsetenv(buf);
        snprintf(buf, sizeof(buf), "PS_ENABLE_%.*s", (int)PS_LOGF_UNIT_MAX_LEN,
                 module_or_level);
        setenv(buf, "1", 0);
    }
    psLogfFlush();
}

/* Disable logging for select levels or modules. */
void psLogfDisable(const char *module_or_level)
{
    char buf[PS_LOGF_UNIT_MAX_LEN + 20];

    if (strlen(module_or_level) <= PS_LOGF_UNIT_MAX_LEN)
    {
        /* use unsetenv/setenv to specify logging settings. */
        snprintf(buf, sizeof(buf), "PS_ENABLE_%.*s", (int)PS_LOGF_UNIT_MAX_LEN,
                 module_or_level);
        unsetenv(buf);
        snprintf(buf, sizeof(buf), "PS_DISABLE_%.*s", (int)PS_LOGF_UNIT_MAX_LEN,
                 module_or_level);
        setenv(buf, "1", 0);
    }
    psLogfFlush();
}
