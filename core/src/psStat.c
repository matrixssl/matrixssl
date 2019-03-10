/* psStat.c
 * Functions for computing misc useful statistics. Work-in-progress.
 *
 */

/*****************************************************************************
* Copyright (c) 2018 INSIDE Secure Oy. All Rights Reserved.
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

#include "osdep.h"
#include "osdep_stdio.h"
#include "psStat.h"
#include "psUtil.h"

psStatCompByteSeqResult_t psStatCompByteSeq(const unsigned char *a,
        const char *aName,
        const unsigned char *b,
        const char *bName,
        psSizeL_t len)
{
    int i;
    int num_diffs = 0;
    int num_common = 0;
    int first_diff_ix = -1;
    int last_diff_ix = 0;
    int longest_diff_run = 0;
    int longest_diff_run_start = 0;
    int longest_match_run = 0;
    int longest_match_run_start = 0;
    int num_longest_match_runs = 0;
    int num_longest_diff_runs = 0;
    int run_len = 0;
    int run_start = 0;
    int num_match_runs = 0;
    int num_diff_runs = 0;
    int sum_match_runs = 0;
    int sum_diff_runs = 0;
    psStatCompByteSeqResult_t res;

    i = 0;
    while (i < len)
    {
        /* Handle runs of common bytes. */
        run_len = 0;
        run_start = i;
        while (i < len && a[i] == b[i])
        {
            i++;
            run_len++;
            num_common++;
            if (run_len > longest_match_run)
            {
                longest_match_run = run_len;
                longest_match_run_start = run_start;
                num_longest_match_runs = 1;
            }
            else if (run_len == longest_match_run)
            {
                num_longest_match_runs++;
            }
        }
        if (i < len)
        {
            num_match_runs++;
            sum_match_runs += run_len;
        }

        /* Handle runs of mismatching bytes. */
        run_len = 0;
        run_start = i;
        while (i < len && a[i] != b[i])
        {
            i++;
            run_len++;
            num_diffs++;
            if (run_len > longest_diff_run)
            {
                longest_diff_run = run_len;
                longest_diff_run_start = run_start;
                num_longest_diff_runs = 1;
            }
            else if (run_len == longest_diff_run)
            {
                num_longest_diff_runs++;
            }
            if (first_diff_ix == -1)
            {
                first_diff_ix = i;
            }
            last_diff_ix = i;
        }
        if (i < len)
        {
            num_diff_runs++;
            sum_diff_runs += run_len;
        }
    }

    psAssert(num_common + num_diffs == len);

    res.a = a;
    res.b = b;
    res.aName = aName;
    res.bName = bName;

    res.len = len;
    res.num_diffs = num_diffs;
    res.num_matches = num_common;
    res.first_diff_ix = first_diff_ix;
    res.last_diff_ix = last_diff_ix;

    res.luss_len = longest_diff_run;
    res.luss_start_ix = longest_diff_run_start;
    res.luss_end_ix =
        longest_diff_run_start + longest_diff_run;
    res.luss_freq = num_longest_diff_runs;

    res.lcss_len = longest_match_run;
    res.lcss_start_ix = longest_match_run_start;
    res.lcss_end_ix =
        longest_match_run_start + longest_match_run;
    res.lcss_freq = num_longest_match_runs;

    res.num_match_runs = num_match_runs;
    if (num_match_runs > 0)
        res.avg_match_run_len = (int)((double)sum_match_runs /
                (double)num_match_runs);
    else
        res.avg_match_run_len = 0;

    res.num_diff_runs = num_diff_runs;
    if (num_diff_runs > 0)
        res.avg_diff_run_len = (int)((double)sum_diff_runs /
                (double)num_diff_runs);
    else
        res.avg_diff_run_len = 0;

    res.filled = 1;

    return res;
}

void psStatPrintCompByteSeqResult(psStatCompByteSeqResult_t res,
        psStatPrintCompByteSeqResultOpts_t *opts)
{
    char buf[4096] = {0};
    char lcssBuf[1024] = {0};
    char lussBufA[1024] = {0};
    char lussBufB[1024] = {0};
    psSizeL_t lcssLen, lussLen;
    psStatPrintCompByteSeqResultOpts_t defaultOpts =
    {
        .lcss_max_prefix_len = 16,
        .luss_max_prefix_len = 16
    };

    if (res.filled != 1)
    {
        return;
    }

    if (opts == NULL)
    {
        opts = &defaultOpts;
    }
    psTraceBytes(res.aName, res.a, res.len);
    psTraceBytes(res.bName, res.b, res.len);

    /* Print prefixes of the longest common and uncommon substrings. */
    lcssLen = res.lcss_len;
    psStatPrintHexSimple(lcssBuf, sizeof(lcssBuf),
            &res.a[res.lcss_start_ix],
            PS_MIN(lcssLen, opts->lcss_max_prefix_len));
    lussLen = res.luss_len;
    psStatPrintHexSimple(lussBufA, sizeof(lussBufA),
            &res.a[res.luss_start_ix],
            PS_MIN(lussLen, opts->lcss_max_prefix_len));
    psStatPrintHexSimple(lussBufB, sizeof(lussBufB),
            &res.b[res.luss_start_ix],
            PS_MIN(lussLen, opts->lcss_max_prefix_len));

    Snprintf(buf,
            sizeof(buf),
            "Total length of compared sequence: %zu\n"  \
            " %d matches\n"                             \
            " %d mismatches\n"                          \
            "  First mismatch at #%d\n"                 \
            "  Last mistmatch at #%d\n"                 \
            " Substring stats:\n"                       \
            "  Number of common substrings: %d\n"       \
            "  Average common substring len: %d\n"      \
            "  Number of uncommon substrings: %d\n"     \
            "  Avarage uncommon substring len: %d\n"    \
            " Longest common substring:\n"              \
            "  length: %d (%d runs of this length)\n"   \
            "  position: #%d to #%d\n"                  \
            "  first bytes: %s\n"                       \
            " Longest uncommon substring:\n"            \
            "  length: %d (%d runs of this length)\n"   \
            "  position: #%d to #%d\n"                  \
            "  first bytes (a): %s\n"                   \
            "  first bytes (b): %s\n",
            res.len,
            res.num_matches,
            res.num_diffs,
            res.first_diff_ix,
            res.last_diff_ix,
            res.num_match_runs,
            res.avg_match_run_len,
            res.num_diff_runs,
            res.avg_diff_run_len,
            res.lcss_len,
            res.lcss_freq,
            res.lcss_start_ix,
            res.lcss_end_ix,
            lcssBuf,
            res.luss_len,
            res.luss_freq,
            res.luss_start_ix,
            res.luss_end_ix,
            lussBufA,
            lussBufB);

    psTraceStr("%s\n", buf);
}

void psStatPrintHexSimple(char *resultBuf,
        psSizeL_t resultBufLen,
        const unsigned char *bytes,
        psSizeL_t bytesLen)
{
    int i;
    int pos = 0;
    psSizeL_t remainingLen = resultBufLen;
    int rc;

    for (i = 0; i < bytesLen; i++)
    {
        rc = Snprintf(resultBuf + pos, remainingLen,
                "%.2hhx ", bytes[i]);
        if (rc < 0)
        {
            return;
        }
        pos += rc;
        remainingLen -= rc;
    }
}

# ifdef PS_STAT_TEST
psRes_t psStatTest(void)
{
    psStatCompByteSeqResult_t compRes;
    unsigned char test1[] =
        {
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        };
    unsigned char test2[] =
        {
            0xbb, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xaa, 0xbb,
        };
    unsigned char test3[] =
        {
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xbb, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xaa,
        };
    psStatPrintCompByteSeqResultOpts_t opts;

    compRes = psStatCompByteSeq(test1, "test1",
            test2, "test2",
            sizeof(test1));
    if (compres.lcss_len != 17)
    {
        return PS_FAILURE;
    }
    opts.lcss_max_prefix_len = 16;
    psPrintCompByteSeqResult(compRes, &opts);

    compRes = psStatCompByteSeq(test1, "test1",
            test3, "test3",
            sizeof(test1));
    if (compRes.lcss_len != 2)
    {
        return PS_FAILURE;
    }

    assert(compRes.lcss_len == 2);
    opts.lcss_max_prefix_len = 16;
    psPrintCompByteSeqResult(compRes, &opts);

    return PS_SUCCESS;
}
# endif /* PS_STAT_TEST */

/* end of file psStat.c */
