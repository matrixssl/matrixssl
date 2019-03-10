/* psStat.h
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\
* http://www.gnu.org/copyleft/gpl.html
*****************************************************************************/

#ifndef INCLUDE_GUARD_PSSTAT_H
#define INCLUDE_GUARD_PSSTAT_H

typedef struct
{
    int filled;
    int num_diffs;
    int num_matches;
    int first_diff_ix;
    int last_diff_ix;
    int num_match_runs;
    int avg_match_run_len;
    int num_diff_runs;
    int avg_diff_run_len;
    /* Longest common substring (LCSS): */
    int lcss_start_ix;
    int lcss_end_ix;
    int lcss_len;
    int lcss_freq;
    /* Longest uncommon substring (LUSS): */
    int luss_start_ix;
    int luss_end_ix;
    int luss_len;
    int luss_freq;
    const unsigned char *a;
    const char *aName;
    const unsigned char *b;
    const char *bName;
    psSizeL_t len;
} psStatCompByteSeqResult_t;

typedef struct
{
    int lcss_max_prefix_len;
    int luss_max_prefix_len;
} psStatPrintCompByteSeqResultOpts_t;

/** Compare two byte sequences and compute statistics, such as the
    number of mismatches, the longest common subsequence, etc.
    The result can be printed with psPrintCompByteSeqResult. */
psStatCompByteSeqResult_t psStatCompByteSeq(const unsigned char *a,
        const char *aName,
        const unsigned char *b,
        const char *bName,
        psSizeL_t len);

/** Print the result of psStatByteSeq. */
void psStatPrintCompByteSeqResult(psStatCompByteSeqResult_t res,
        psStatPrintCompByteSeqResultOpts_t *opts);

/** Simple hex dump without extra printouts (c.f. psTraceBytes). */
void psStatPrintHexSimple(char *resultBuf,
        psSizeL_t resultBufLen,
        const unsigned char *bytes,
        psSizeL_t bytesLen);

#endif /* INCLUDE_GUARD_PSSTAT_H */

/* end of file psStat.h */
