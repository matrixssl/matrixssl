/* ocspTest.c
 *
 * Test OCSP APIs.
 */

/*****************************************************************************
* Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <stdint.h>

#include "crypto/cryptoApi.h"
#include "core/coreApi.h"

#include "ocspTestData.h"

#define MAX_EXTRA_INFO 128
typedef enum { OK, FAILED, WEAK, SKIPPED } TEST_RESULT;

int write_debug_files;

# define NOT_SUPPORTED(func_proto) func_proto { \
        return failf("Functionality is currently missing"); \
} \
    extern int require_semicolon[1]

static char extra_info[MAX_EXTRA_INFO];

int test(int condition)
{
    /* This function is provided as convenience for setting
       breakpoint(s). */
    return condition;
}

int fail(void)
{
    /* This function is provided as convenience for setting
       breakpoint(s). */
    return FAILED;
}

int failf(const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    vsnprintf(extra_info, sizeof(extra_info), fmt, va);
    va_end(va);
    return FAILED;
}

int okf(const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    vsnprintf(extra_info, sizeof(extra_info), fmt, va);
    va_end(va);
    return OK;
}

int fail_at(const char *file, int line, const char *cond)
{
    /* This function is provided as convenience for setting
       breakpoint(s) and for debug output. */
    fprintf(stderr, "Failure detected at %s:%d: %s\n", file, line, cond);
    return fail();
}

#define FAIL_IF(condition)                      \
    do {                                \
        if (test(condition)) {                    \
            return fail_at(__FILE__, __LINE__, #condition); } \
    } while (0)

/* Check existance of function. Fails if the function does not exist. */
#define CHECK_EXISTS(fun)                                           \
    do {                                                            \
        void *ptr = &fun;                                           \
        if (!ptr) {                                                 \
            return failf("Unable to locate function "#fun "\n");     \
        }                                                           \
    } while (0)

/* #define VERBOSE(...) do { printf(__VA_ARGS__); } */
#define VERBOSE(...) do { } while (0)

/* Give alias (alternative name) for function. */
#define TEST_ALT_NAME(new_name, old_name) \
    TEST_RESULT new_name(void)            \
    {                                     \
        return old_name();                \
    }                                     \
    TEST_RESULT new_name(void)

/* Test is intended to run only once and cache the results.
   This is to be used TEST_ALT_NAME().
   Warning: this macro may call return (i.e. affect control flow). */
#define TEST_ONCE(fun)                                        \
    do                                                        \
    {                                                         \
        static unsigned long long test_once_called_times = 0; \
        static TEST_RESULT test_once_result_cached = SKIPPED; \
        test_once_called_times ++;                            \
                                                              \
        switch (test_once_called_times)                       \
        {                                                     \
        case 1:                                               \
            /* Ensure correct function name used. */          \
            assert(strcmp(#fun, __func__) == 0);              \
            test_once_result_cached = fun ();                 \
            /* fall-through */                                \
        default:                                              \
            return test_once_result_cached;                   \
        case 2:                                               \
            /* actual execution of the function. */           \
            break;                                            \
        }                                                     \
    } while (0)                                               \

void opt_WRITE_FILE(const char *target,
                const void *data,
                size_t data_length)
{
    FILE *f;

    if (!write_debug_files)
    {
        return; /* Do not produce debugging files. */
    }

    f = fopen(target, "w");
    if (f)
    {
        if (fwrite(data, data_length, 1, f) != 1)
        {
            fprintf(stderr, "write error\n");
            exit(1);
        }
        fprintf(stderr, "(Written %lu data bytes to %s)\n",
                (long unsigned int) data_length, target);
    }
    fclose(f);
}

TEST_RESULT TEST_psOcspRequestWrite(void)
{
    psRes_t res;
    psX509Cert_t *revoked_psX509certificate;
    psX509Cert_t *issuer_psX509certificate;
    uint32 requestLen;
    unsigned char *request = NULL;

    res = psX509ParseCert(
            NULL,
            revoked_certificate,
            sizeof revoked_certificate,
            &revoked_psX509certificate, 0);
    FAIL_IF(res < 0);
    res = psX509ParseCert(
            NULL,
            intermediate_certificate,
            sizeof intermediate_certificate,
            &issuer_psX509certificate, 0);
    FAIL_IF(res < 0);
    res = psOcspRequestWrite(MATRIX_NO_POOL,
                             revoked_psX509certificate,
                             issuer_psX509certificate,
                             &request, &requestLen, NULL);
    FAIL_IF(res < 0);
    opt_WRITE_FILE("/tmp/request", request, requestLen);
    FAIL_IF(memcmp(request, ocsp_request, sizeof ocsp_request) != 0);
    psX509FreeCert(revoked_psX509certificate);
    psX509FreeCert(issuer_psX509certificate);
    psFree(request, MATRIX_NO_POOL);
    return OK;
}

TEST_RESULT TEST_psOcspParseResponse(void)
{
    psRes_t res;
    psX509Cert_t *revoked_psX509certificate;
    psX509Cert_t *issuer_psX509certificate;
    unsigned char *p = ocsp_response;
    int resp_len = ocsp_response_len;
    int32_t res32;
    psOcspResponse_t response;

    res = psX509ParseCert(
            NULL,
            revoked_certificate,
            sizeof revoked_certificate,
            &revoked_psX509certificate, 0);
    FAIL_IF(res < 0);
    res = psX509ParseCert(
            NULL,
            intermediate_certificate,
            sizeof intermediate_certificate,
            &issuer_psX509certificate, 0);
    FAIL_IF(res < 0);

    res32 = psOcspParseResponse(NULL, resp_len, &p, p + resp_len,
                                &response);
    FAIL_IF(res32 < 0);
    FAIL_IF(psOcspResponseGetStatus(res32) != 0);
    psOcspResponseUninit(&response);
    psX509FreeCert(revoked_psX509certificate);
    psX509FreeCert(issuer_psX509certificate);
    return OK;
}
        
TEST_RESULT TEST_psOcspResponseCheckDatesCommon(
        unsigned char *p,
        int resp_len,
        psRes_t res_expect,
        struct tm *timeNow_p,
        struct tm *ProducedAt_p,
        struct tm *thisUpdate_p,
        struct tm *nextUpdate_p)
{
    psRes_t res;
    psX509Cert_t *revoked_psX509certificate;
    psX509Cert_t *issuer_psX509certificate;
    int32_t res32;
    psOcspResponse_t response;
    int32 index = 0;

    res = psX509ParseCert(
            NULL,
            revoked_certificate,
            sizeof revoked_certificate,
            &revoked_psX509certificate, 0);
    FAIL_IF(res < 0);
    res = psX509ParseCert(
            NULL,
            intermediate_certificate,
            sizeof intermediate_certificate,
            &issuer_psX509certificate, 0);
    FAIL_IF(res < 0);

    res32 = psOcspParseResponse(NULL, resp_len, &p, p + resp_len,
                                &response);
    FAIL_IF(res32 < 0);
    res32 = psOcspResponseCheckDates(&response,
                                     index,
                                     timeNow_p,
                                     ProducedAt_p,
                                     thisUpdate_p,
                                     nextUpdate_p,
                                     PS_OCSP_TIME_LINGER);

    FAIL_IF(res32 != res_expect);
    psOcspResponseUninit(&response);
    psX509FreeCert(revoked_psX509certificate);
    psX509FreeCert(issuer_psX509certificate);
    return OK;
}

TEST_RESULT TEST_psOcspResponseCheckDates(void)
{
    struct tm timeNow = { 0 };
    struct tm ProducedAt = { 0 };
    struct tm thisUpdate = { 0 };
    struct tm nextUpdate = { 0 };
    TEST_RESULT res;
    
    res = TEST_psOcspResponseCheckDatesCommon(
            ocsp_response,
            ocsp_response_len,
            PS_SUCCESS,
            &timeNow,
            &ProducedAt,
            &thisUpdate,
            &nextUpdate);

    if (res == OK)
    {
        FAIL_IF(
                ProducedAt.tm_year != 117 ||
                ProducedAt.tm_mon != 2 ||
                ProducedAt.tm_mday != 27 ||
                ProducedAt.tm_hour != 6 ||
                ProducedAt.tm_min != 0 ||
                ProducedAt.tm_sec != 0);

        FAIL_IF(
                thisUpdate.tm_year != 117 ||
                thisUpdate.tm_mon != 2 ||
                thisUpdate.tm_mday != 27 ||
                thisUpdate.tm_hour != 6 ||
                thisUpdate.tm_min != 0 ||
                thisUpdate.tm_sec != 0);

        FAIL_IF(
                nextUpdate.tm_year != 117 ||
                nextUpdate.tm_mon != 2 ||
                nextUpdate.tm_mday != 27 ||
                nextUpdate.tm_hour != 6 ||
                nextUpdate.tm_min != 5 ||
                nextUpdate.tm_sec != 0);
    }
    return res;
}

TEST_RESULT TEST_psOcspResponseCheckDates_future(void)
{
    struct tm timeNow = { 0 };
    struct tm ProducedAt = { 0 };
    struct tm thisUpdate = { 0 };
    struct tm nextUpdate = { 0 };
    TEST_RESULT res;
    
    res = TEST_psOcspResponseCheckDatesCommon(
            ocsp_response_future,
            ocsp_response_future_len,
            PS_TIMEOUT_FAIL,
            &timeNow,
            &ProducedAt,
            &thisUpdate,
            &nextUpdate);

    if (res == OK)
    {
        FAIL_IF(
                ProducedAt.tm_year != 117 ||
                ProducedAt.tm_mon != 2 ||
                ProducedAt.tm_mday != 28 ||
                ProducedAt.tm_hour != 4 ||
                ProducedAt.tm_min != 13 ||
                ProducedAt.tm_sec != 8);

        FAIL_IF(
                thisUpdate.tm_year != 117 ||
                thisUpdate.tm_mon != 2 ||
                thisUpdate.tm_mday != 28 ||
                thisUpdate.tm_hour != 4 ||
                thisUpdate.tm_min != 13 ||
                thisUpdate.tm_sec != 8);

        FAIL_IF(
                nextUpdate.tm_year != 117 ||
                nextUpdate.tm_mon != 2 ||
                nextUpdate.tm_mday != 28 ||
                nextUpdate.tm_hour != 4 ||
                nextUpdate.tm_min != 18 ||
                nextUpdate.tm_sec != 8);
    }
    return res;
}

TEST_RESULT TEST_psOcspResponseValidateCommon(
        unsigned char *p,
        int resp_len,
        psRes_t res_expect,
        psValidateOCSPResponseOptions_t *opts_p)
{
    psRes_t res;
    psX509Cert_t *revoked_psX509certificate;
    psX509Cert_t *issuer_psX509certificate;
    int32_t res32;
    psOcspResponse_t response;

    res = psX509ParseCert(
            NULL,
            revoked_certificate,
            sizeof revoked_certificate,
            &revoked_psX509certificate, 0);
    FAIL_IF(res < 0);
    res = psX509ParseCert(
            NULL,
            intermediate_certificate,
            sizeof intermediate_certificate,
            &issuer_psX509certificate, 0);
    FAIL_IF(res < 0);

    res32 = psOcspParseResponse(NULL, resp_len, &p, p + resp_len,
                                &response);
    FAIL_IF(res32 < 0);
    res32 = psOcspResponseValidate(
            NULL,
            issuer_psX509certificate,
            revoked_psX509certificate,
            &response,
            opts_p);
    FAIL_IF(res32 != res_expect);
    psOcspResponseUninit(&response);
    psX509FreeCert(revoked_psX509certificate);
    psX509FreeCert(issuer_psX509certificate);
    return OK;
}

TEST_RESULT TEST_psOcspResponseValidate(void)
{
    return TEST_psOcspResponseValidateCommon(
            ocsp_response,
            ocsp_response_len,
            PS_CERT_AUTH_FAIL_REVOKED,
            NULL);
}

TEST_RESULT TEST_psOcspResponseValidate_future(void)
{
    return TEST_psOcspResponseValidateCommon(
            ocsp_response_future,
            ocsp_response_future_len,
            PS_FAILURE, /* The response is invalid (in future). */
            NULL);
}

TEST_RESULT TEST_psOcspResponseValidate_sha512(void)
{
    return TEST_psOcspResponseValidateCommon(
            ocsp_response_sha512,
            ocsp_response_sha512_len,
            PS_CERT_AUTH_FAIL_REVOKED,
            NULL);
}

int test_match(int argc, char **argv, const char *string)
{
    int i;

    if (argc == 1)
    {
        return 1;
    }

    for (i = 1; i < argc; i++)
    {
        if (argv[i] != NULL && !strcmp(argv[i], string))
        {
            argv[i] = NULL;
            return 1;
        }
    }

    return 0;
}

#define TEST(fun)                                                   \
    do {                                                            \
        int res;                                                    \
        if (argc == 2 && argv[1] != NULL &&                         \
            !strcmp(argv[1], "--list")) {                           \
            printf("%s\n", #fun);                                   \
            break;                                                  \
        } else if (test_match(argc, argv, #fun)) {                  \
            printf("%s ... ", #fun);                                \
            fflush(stdout);                                         \
            res = fun();                                            \
            counter[(int) res]++;                                   \
            printf("%s%s%s%s\n", res == OK ? "OK" :                  \
                res == WEAK ? "OK (but size considered weak)" :  \
                res == SKIPPED ? "OK (not supported)" :          \
                "FAILED", extra_info[0] ? " (" : "", extra_info,   \
                extra_info[0] ? ")" : "");                         \
            extra_info[0] = 0;                                      \
        }                                                           \
    } while (0)

int main(int argc, char **argv)
{
    int counter[4] = { 0, 0, 0, 0 };
    int do_list = 0;

    time_t currentTime = time(NULL);
    if (currentTime < 1490594400 || currentTime > 1490594420)
    {
        fprintf(stderr, "This test is designed to run via faketime.\n"
                "Please set time to 2017-03-27 09:00:00 EET.\n");
        exit(1);
    }
    
#ifdef USE_MTRACE
    if (getenv("MALLOC_TRACE"))
    {
        mtrace();
    }
#endif /* USE_MTRACE */

    if (argc == 2 && !strcmp(argv[1], "--list"))
    {
        printf("Tests available:\n");
        do_list = 1;
    }
    else
    {
        printf("Testing OCSP:\n");
    }

    /* Init the MatrixSSL's crypto library */
    if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS)
    {
        fprintf(stderr, "psCryptoOpen failed: unable to test ocsp.\n");
        exit(1);
    }

/* Template:    TEST(TEST_function); */

    TEST(TEST_psOcspRequestWrite);
    TEST(TEST_psOcspParseResponse);
    TEST(TEST_psOcspResponseCheckDates);
    TEST(TEST_psOcspResponseCheckDates_future);
    TEST(TEST_psOcspResponseValidate);
    TEST(TEST_psOcspResponseValidate_future);
    TEST(TEST_psOcspResponseValidate_sha512);
    
    /* Add test invocations here... */

#ifdef USE_MTRACE
    if (getenv("MALLOC_TRACE"))
    {
        muntrace();
    }
#endif /* USE_MTRACE */

    psCryptoClose();

    if (do_list)
    {
        return 0;
    }

    counter[(int) OK] += counter[(int) WEAK];
    {
        int counter_sum = counter[(int) OK] + counter[(int) WEAK] +
                          counter[(int) FAILED] + counter[(int) SKIPPED];
        printf("Ok tests: %d/%d\n", counter[(int) OK], counter_sum);
        if (counter[(int) WEAK])
        {
            printf("... %d of Ok tests resulted \"WEAK security\" warning\n",
                counter[(int) WEAK]);
        }
        if (counter[(int) FAILED])
        {
            printf("Failed tests: %d/%d\n", counter[(int) FAILED], counter_sum);
        }
        if (counter[(int) SKIPPED])
        {
            printf("Skipped tests: %d/%d\n", counter[(int) SKIPPED],
                counter_sum);
        }
    }
    counter[(int) OK] += counter[(int) SKIPPED];
    return counter[(int) OK] == 0 || counter[(int) FAILED] != 0;
}


/* end of file ocspTest.c */

    
