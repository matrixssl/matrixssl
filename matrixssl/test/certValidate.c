/**
 *      @file   certValidate.c
 *      @version $Format:%h%d$
 *
 *      Standalone certificate parsing and chain validation test.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
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
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200112L
#endif

#include "osdep_unistd.h"
#include "osdep_stdio.h"
#include "matrixssl/matrixsslApi.h"
#include "psUtil.h"

/****************************** Local Functions *******************************/

#if defined(USE_CERT_VALIDATE) && defined(MATRIX_USE_FILE_SYSTEM)

/*
    @example
    ./certValidate -c '../../testkeys/RSA/2048_RSA_CA.pem' -n 'localhost' ../../testkeys/RSA/2048_RSA.pem
    ./certValidate ../../testkeys/RSA/2048_RSA_CA.pem
 */
static void usage(void)
{
    Printf(
        "\nusage: certValidate { options } <file>\n"
        "  options can be one or more of the following:\n"
        "    -c <file>           - Root CA certificate file\n"
        "                          Default: Root CA validation skipped\n"
        "    -s [subject]        - Subject name to validate (eg www.example.com)\n"
        "                          Default: Subject validation skipped\n"
        "    -f [pem|eff|sonar]  - File format. Non-pem options imply scan mode\n"
        "                          Default: pem\n"
        "  additional scan mode options:\n"
        "    -l [lineno]         - Process single line from scan file (first line is 1)\n"
        "    -d                  - Dump DER output for failed certs in scan file\n"
        "    -S                  - Produce/compare scan summary file in <file>.log\n"
        "  example: certValidate -c ca_certs.pem -s www.matrixssl.org cert_chain.pem\n"
        "\n");
}

/* Command line parameters, point directly in to argv[] */
char *g_cafile = NULL;   /* Optional root CA file */
char *g_certfile = NULL; /* Cert chain file */
char *g_subject = NULL;  /* Optional cert subject name to validate */

int g_pem = 0;           /* Process a PEM certifiate file */
int g_sonar = 0;         /* Process a Sonar certifiate scan file */
int g_eff = 0;           /* Process an EFF certifiate scan file */
int g_summary = 0;       /* Output/compare a summary file */
int g_der = 0;           /* Output DER files when appropriate */
int g_line = 0;          /* Process a single line from certificate scan */

static int32_t process_cmd_options(int argc, char **argv)
{
    int optionChar;
    char *e;

    while ((optionChar = getopt(argc, argv, "c:df:l:s:S")) != -1)
    {
        switch (optionChar)
        {

        /* Optional filenae containing trusted root certificate(s) */
        case 'c':
            if (g_cafile)
            {
                Printf("Multiple options '-%c'\n", optionChar);
                return -1;
            }
            g_cafile = optarg;
            break;

        /* Optional name to validate for certificate subject */
        case 's':
            if (g_subject)
            {
                Printf("Multiple options '-%c'\n", optionChar);
                return -1;
            }
            g_subject = optarg;
            break;

        /* Optional Project Sonar mode */
        case 'f':
            if (g_pem + g_eff + g_sonar != 0)
            {
                Printf("Multiple options '-%c'\n", optionChar);
                return -1;
            }
            if (Strcmp(optarg, "pem") == 0)
            {
                g_pem = 1;
            }
            else if (Strcmp(optarg, "eff") == 0)
            {
                g_eff = 1;
                Printf("NOT CURRENTLY SUPPORTED '-%c %s'\n", optionChar, optarg);
                return -1;
            }
            else if (Strcmp(optarg, "sonar") == 0)
            {
                g_sonar = 1;
            }
            else
            {
                Printf("Unknown argument '-%c %s'\n", optionChar, optarg);
                return -1;
            }
            break;

        /* Select single line (when rprocessing scan files) */
        case 'l':
            g_line = Strtol(optarg, &e, 10);
            if (e != (optarg + Strlen(optarg))
                || g_line <= 0)
            {
                Printf("Invalid argument '-%c %s'\n", optionChar, optarg);
                return -1;
            }
            break;

        case 'S':
            g_summary = 1;
            break;

        /* Dump DER files (when processing scan files) */
        case 'd':
            g_der = 1;
            break;

        default:
            Printf("Unknown option '-%c'\n", optionChar);
            return -1;
        }
    }
    if (optind != argc - 1)
    {
        Printf("Exactly one cert chain file must be provided.\n");
        return -1;
    }
    g_certfile = argv[optind];
    if (g_pem + g_eff + g_sonar == 0)
    {
        g_pem = 1;
    }
    if (g_pem)
    {
        if (g_line > 0)
        {
            Printf("Ignoring -l argument in PEM mode.\n");
        }
        if (g_der > 0)
        {
            Printf("Ignoring -d argument in PEM mode.\n");
        }
        if (g_summary > 0)
        {
            Printf("Ignoring -S argument in PEM mode.\n");
        }
    }
    return PS_SUCCESS;
}

static char *flagstostr(int flags)
{
    static char f[80];  /* Not reentrant, but good enough for this test */
    char *s = f;

    if (flags)
    {
        s += Sprintf(s, " (");
        if (flags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG)
        {
            s += Sprintf(s, "KEY_USAGE ");
        }
        if (flags & PS_CERT_AUTH_FAIL_EKU_FLAG)
        {
            s += Sprintf(s, "EXTENDED_KEY_USAGE ");
        }
        if (flags & PS_CERT_AUTH_FAIL_SUBJECT_FLAG)
        {
            s += Sprintf(s, "SUBJECT ");
        }
        if (flags & PS_CERT_AUTH_FAIL_DATE_FLAG)
        {
            s += Sprintf(s, "DATE ");
        }
        Sprintf(s, ")");
        return f;
    }
    return "";
}

static char *errtostr(int rc)
{
    static char e[80];  /* Not reentrant, but good enough for this test */

    switch (rc)
    {
    case 0:
    case PS_CERT_AUTH_PASS:
        return "PASS";
    case PS_PARSE_FAIL:
        return "FAIL Parse";
    case PS_CERT_AUTH_FAIL_BC:
        return "FAIL Basic Constraints";
    case PS_CERT_AUTH_FAIL_DN:
        return "FAIL Distinguished Name Match";
    case PS_CERT_AUTH_FAIL_SIG:
        return "FAIL Signature Validation";
    case PS_CERT_AUTH_FAIL_REVOKED:
        return "FAIL Certificate Revoked";
    case PS_CERT_AUTH_FAIL:
        return "FAIL Authentication Fail";
    case PS_CERT_AUTH_FAIL_EXTENSION:
        return "FAIL Extension";
    case PS_CERT_AUTH_FAIL_PATH_LEN:
        return "FAIL Path Length";
    case PS_CERT_AUTH_FAIL_AUTHKEY:
        return "FAIL Auth Key / Subject Key Match";
    default:
        Sprintf(e, "FAIL %d", rc);
        return e;
    }
}

# define PARSE_STATUS(A) { A, #A, 0 }

static struct
{
    parse_status_e id;
    const char name[32];
    int count;
} parse_status[] = {
    PARSE_STATUS(PS_X509_PARSE_SUCCESS),
    PARSE_STATUS(PS_X509_PARSE_FAIL),
    PARSE_STATUS(PS_X509_WEAK_KEY),
    PARSE_STATUS(PS_X509_UNSUPPORTED_VERSION),
    PARSE_STATUS(PS_X509_UNSUPPORTED_ECC_CURVE),
    PARSE_STATUS(PS_X509_UNSUPPORTED_SIG_ALG),
    PARSE_STATUS(PS_X509_UNSUPPORTED_KEY_ALG),
    PARSE_STATUS(PS_X509_UNSUPPORTED_EXT),
    PARSE_STATUS(PS_X509_DATE),
    PARSE_STATUS(PS_X509_MISSING_NAME),
    PARSE_STATUS(PS_X509_MISSING_RSA),
    PARSE_STATUS(PS_X509_ALG_ID),
    PARSE_STATUS(PS_X509_ISSUER_DN),
    PARSE_STATUS(PS_X509_SIGNATURE),
    PARSE_STATUS(PS_X509_SUBJECT_DN),
    PARSE_STATUS(PS_X509_EOF),
    PARSE_STATUS(PS_X509_SIG_MISMATCH),
    { (parse_status_e) 0 } /* List terminator */
};

/******************************************************************************/
/**
    Process internet wide certificate scans from Project Sonar.
    Supports uncompressed *_certs.gz files.
    @see https://scans.io/study/sonar.ssl
 */
static void write_summary(FILE *fp)
{
    int i, total = 0;

    for (i = 0; *parse_status[i].name; i++)
    {
        total += parse_status[i].count;
    }
    for (i = 0; *parse_status[i].name; i++)
    {
        Fprintf(fp, "%12d %3d %s\n",
            parse_status[i].count,
            (parse_status[i].count * 100) / total,
            parse_status[i].name);
    }
}

# define CERT_MAX_BYTES  (1024 * 32)/* Must be < 64K for base64decode */

static int32_t process_sonar(void)
{
    FILE *fp, *wfp;
    char buf[CERT_MAX_BYTES];
    char certbuf[CERT_MAX_BYTES];        /* Could be smaller due to base64 decode */
    char outfile[32] = { 0 };
    char *certhash, *cert64;
    int32_t certhashlen, cert64len;
    psSize_t certbuflen;
    int32_t rc = 0, line = 0;
    psX509Cert_t *cert;

    if ((fp = Fopen(g_certfile, "r")) == NULL)
    {
        perror("Error opening file");
        return -1;
    }
    while (fgets(buf, CERT_MAX_BYTES, fp) != NULL)
    {
        line++;
        if (g_line > 0)
        {
            if (line < g_line)
            {
                continue;   /* Skip lines before selected one */
            }
            if (line > g_line)
            {
                break;      /* Stop processing after selected line */
            }
        }
        certhash = buf;
        cert64 = Strchr(buf, ',');
        if (*cert64 == '\0')
        {
            Printf("CSV parse failed on line %d\n", line);
            Fclose(fp);
            return -1;
        }
        *cert64 = '\0';
        cert64++;
        certhashlen = Strlen(certhash);
        cert64len = Strlen(cert64);
        if (certhashlen + cert64len + 2 >= CERT_MAX_BYTES)
        {
            Printf("CERT_MAX_BYTES exceeded on line %d\n", line);
            Fclose(fp);
            return -1;
        }

        certbuflen = CERT_MAX_BYTES;
#ifdef USE_BASE64_DECODE
        if (psBase64decode((unsigned char *) cert64, cert64len, (unsigned char *) certbuf, &certbuflen) != 0)
        {
            Printf("Base64 parse failed on line %d\n", line);
            Fclose(fp);
            return -1;
        }
        if (certbuflen > SSL_MAX_PLAINTEXT_LEN)
        {
            Printf("WARNING, %d byte cert\n", certbuflen);
        }
#else
        memcpy(certbuf, cert64, cert64len);
        certbuflen = cert64len;
#endif
        if ((rc = psX509ParseCert(NULL, (unsigned char *) certbuf, certbuflen, &cert, 0)) < 0)
        {
            /* Output the cert we couldn't process. It can be viewd by openssl using:
                openssl x509 -inform der -text -in SONAR_<num>.der */
            if (!cert)
            {
                Printf("X509 Memory allocation failed for line %d\n", line);
                Fclose(fp);
                return -1;
            }
            switch (cert->parseStatus)
            {
            /* Additional diagnostics for certificate failures */
            case PS_X509_MISSING_NAME:
                /* TODO print other name components */
                break;
            case PS_X509_DATE:
                if (!g_summary)
                {
                    Printf("%s-%s\n", cert->notBefore, cert->notAfter);
                }
                break;
            default:
                break;
            }
            if (!g_summary)
            {
                Printf("%12d:X509 %s (%s)\n", line, errtostr(rc),
                    parse_status[cert->parseStatus].name);
            }
            if (g_der)
            {
                Snprintf(outfile, 31, "SONAR_%012d.der", line);
                if ((wfp = Fopen(outfile, "w")) != NULL)
                {
                    if (Fwrite(certbuf, certbuflen, 1, wfp) != 1)
                    {
                        perror("Error writing file");
                    }
                    Fclose(wfp);
                }
                else
                {
                    perror("Error creating file");
                }
            }
            parse_status[cert->parseStatus].count++;
            psX509FreeCert(cert);
            continue;
        }
        psAssert(cert->authStatus == 0);
        if (!g_summary)
        {
            Printf("%12d:%s\n", line, cert->subject.commonName);
        }
        parse_status[cert->parseStatus].count++;
        psX509FreeCert(cert);
    }
    Fclose(fp);
    if (g_line > 0)
    {
        if (line == (g_line + 1))
        {
            Printf("Processed line %d of %s\n", g_line, g_certfile);
        }
        else
        {
            Printf("Error, line %d not found in %s\n", g_line, g_certfile);
        }
    }
    else
    {
        Printf("%d certificates processed\n", line);
    }
    if (!line)
    {
        return 0;
    }
    Printf("Cert Count    %%  Parse Status\n");
    if (g_summary)
    {
        FILE *lfp = NULL, *tfp = NULL;
        char *lfname = NULL;
        char *tfname = NULL;
        lfname = Malloc(Strlen(g_certfile) + 5); /* 5 is .log\0 */
        Sprintf(lfname, "%s.log", g_certfile);
        if ((lfp = Fopen(lfname, "r")) == NULL)
        {
            /* No existing log file, create it */
            if ((lfp = Fopen(lfname, "w")) == NULL)
            {
                perror("Error opening file");
                Free(lfname);
                return -1;
            }
            write_summary(lfp);
            Fclose(lfp);
            Printf("Wrote log file %s\n", lfname);
        }
        else
        {
            int match = 1;
            /* Found log file, create a tmp comparison file */
            tfname = Malloc(Strlen(lfname) + 5); /* 5 is .tmp\0 */
            Sprintf(tfname, "%s.tmp", lfname);
            if ((tfp = Fopen(tfname, "w+")) == NULL)
            {
                perror("Error opening file");
                Fclose(lfp);
                Free(lfname);
                Free(tfname);
                return -1;
            }
            write_summary(tfp);
            rewind(tfp);
            while (fgets(buf, CERT_MAX_BYTES, lfp) != NULL)
            {
                if (fgets(certbuf, CERT_MAX_BYTES, tfp) == NULL)
                {
                    match = 0;
                    break;
                }
                if (Strncmp(buf, certbuf, CERT_MAX_BYTES) != 0)
                {
                    match = 0;
                    break;
                }
            }
            if (fgets(certbuf, CERT_MAX_BYTES, tfp) != NULL)
            {
                match = 0;
            }
            Fclose(lfp);
            Fclose(tfp);
            if (unlink(tfname) < 0)
            {
                perror("Error unlink file");
                Free(lfname);
                Free(tfname);
                return -1;
            }
            if (match)
            {
                Printf("MATCH Success for %s\n", lfname);
            }
            else
            {
                Printf("MATCH FAIL for %s\n", lfname);
                Free(lfname);
                Free(tfname);
                return -1;
            }
        }
        Free(lfname);
        Free(tfname);
    }
    else
    {
        write_summary(stdout);
    }

    return 0;
}

/******************************************************************************/
/*
    Certificate validation test
 */
int main(int argc, char **argv)
{
    psX509Cert_t *trusted, *chain, *cert;
    psPool_t *pool;
    int32 rc, i;
    uint32 faildate, flags, depth;

    rc = -1;
    faildate = 0;
    pool = NULL;
    trusted = chain = NULL;

    if (process_cmd_options(argc, argv) < 0)
    {
        usage();
        return EXIT_FAILURE;
    }

    if ((rc = matrixSslOpen()) < 0)
    {
        Fprintf(stderr, "MatrixSSL library init failure.  Exiting\n");
        return EXIT_FAILURE;
    }

    if (g_cafile)
    {
        if ((rc = psX509ParseCertFile(pool, g_cafile, &trusted, 0)) < 0)
        {
            if (rc == PS_PLATFORM_FAIL)
            {
                Printf("FAIL open file %s %d\n", g_cafile, rc);
            }
            else
            {
                Printf("FAIL parse %s %d\n", g_cafile, rc);
            }
            goto L_EXIT;
        }
        Printf("  Loaded root file %s\n", g_cafile);
        for (cert = trusted, i = 0; cert != NULL; cert = cert->next, i++)
        {
            Printf("    [%d]:%s\n", i, cert->subject.commonName);
            psAssert(cert->authStatus == 0);
            faildate |= cert->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG;
            psAssert((cert->authFailFlags & ~faildate) == 0);
        }
    }

    if (g_sonar)
    {
        rc = process_sonar();
        goto L_EXIT;
    }

    if ((rc = psX509ParseCertFile(pool, g_certfile, &chain, 0)) < 0)
    {
        if (rc == PS_PLATFORM_FAIL)
        {
            Printf("FAIL open file %s %d\n", g_certfile, rc);
        }
        else
        {
            Printf("FAIL parse %s %d\n", g_certfile, rc);
        }
        goto L_EXIT;
    }
    Printf("  Loaded chain file %s\n", g_certfile);
    for (cert = chain, i = 0; cert != NULL; cert = cert->next, i++)
    {
        Printf("        [%d]:%s\n", i, cert->subject.commonName);
        psAssert(cert->authStatus == 0);
        faildate |= cert->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG;
        psAssert((cert->authFailFlags & ~faildate) == 0);
    }

    if (g_subject)
    {
        if (psX509ValidateGeneralName(g_subject) < 0)
        {
            Printf("FAIL validate general name %s\n", g_subject);
            goto L_EXIT;
        }
    }
    else
    {
        Printf("WARN subject not provided, SUBJ validation will be skipped\n");
    }
    rc = matrixValidateCerts(pool, chain, trusted, g_subject, &cert, NULL, NULL);
    if (rc < 0)
    {
        /* This check is here rather than above to allow self signed certs to pass without
            specifiying a CA */
        if (!trusted && rc == PS_CERT_AUTH_FAIL_DN)
        {
            Printf("WARN Certificates parsed, but cannot be validated against any root cert\n");
            rc = PS_SUCCESS;
            goto L_EXIT;
        }
        Printf("%s\n", errtostr(rc));
        for (cert = chain, i = 0; cert != NULL; cert = cert->next, i++)
        {
            Printf("  Validate:%s[%d]:%s FAIL %d, status=%d, flags=%u\n",
                g_certfile, i, cert->subject.commonName, rc,
                cert->authStatus, cert->authFailFlags);
            if (cert->authStatus != PS_CERT_AUTH_PASS)
            {
                Printf("        authStatus %s\n", errtostr(cert->authStatus));
            }
            if (cert->authFailFlags)
            {
                Printf("        authFailFlags %s\n", flagstostr(cert->authFailFlags));
            }
        }
        goto L_EXIT;
    }
    /* If faildate is set and we don't have an error in rc... */
    psAssert(faildate == 0);

    flags = depth = 0;
    if (cert)
    {
        Printf("  Validate %s:%s rc %d\n", g_certfile, cert->subject.commonName, rc);
    }
    for (cert = chain, i = 0; cert != NULL; cert = cert->next, i++)
    {
        Printf("        [%d] authStatus=%d, authFailFlags=%u\n",
            i, cert->authStatus, cert->authFailFlags);
        if (cert->authStatus != PS_CERT_AUTH_PASS)
        {
            depth = i;
            rc = cert->authStatus;
            flags |= cert->authFailFlags;
        }
        else
        {
            psAssert(cert->authFailFlags == 0);
        }
    }
    if (rc < 0)
    {
        Printf("%s%s in %s[%d]\n", errtostr(rc), flagstostr(flags),
            g_certfile, depth);
        goto L_EXIT;
    }
    Printf("PASS\n");

L_EXIT:
    if (trusted)
    {
        psX509FreeCert(trusted);
    }
    if (chain)
    {
        psX509FreeCert(chain);
    }
    matrixSslClose();

    if (rc < 0)
    {
        return EXIT_FAILURE;
    }
    return 0;
}

#else

int main(int argc, char **argv)
{
# ifndef USE_CERT_PARSE
    Printf("Please enable USE_CERT_PARSE for this test\n");
# endif
# ifndef USE_MATRIX_FILE_SYSTEM
    Printf("Please enable USE_MATRIX_FILE_SYSTEM for this test\n");
# endif
# ifdef USE_ONLY_PSK_CIPHER_SUITE
    Printf("Not applicable when USE_ONLY_PSK_CIPHER_SUITE defined\n");
# endif
# if !defined(USE_CLIENT_SIDE_SSL) && !defined(USE_CLIENT_AUTH)
    Printf("Certificate validation requires either USE_CLIENT_SIDE_SSL " \
        "or USE_CLIENT_AUTH. Please enable one of those\n");
# endif
    return EXIT_FAILURE;
}

#endif /* USE_CERT_VALIDATE && MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/
