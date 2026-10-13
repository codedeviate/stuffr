/* Generator for table.txt: zstd 1.5.7's progress lines from fixed counters.
 *
 * UTIL_makeHumanReadableSize is copied verbatim from zstd 1.5.7
 * programs/util.c; the two printf layouts are those of
 * FIO_compressZstdFrame (fileio.c, "display notification") and
 * FIO_decompressZstdFrame (fileio.c, DISPLAYUPDATE_PROGRESS), kept
 * statement for statement. zstd is BSD-3-Clause / GPL-2.0 dual licensed.
 *
 * Input (stdin), one record per line, fields separated by single spaces:
 *   compress   DISPLAYLEVEL NBFILES IDX NAME FILESIZE|-1 LEVEL INGESTED CONSUMED PRODUCED
 *   decompress DISPLAYLEVEL NBFILES IDX NAME BYTES
 * (IDX is currFileIdx, zero based.)  Output: the record, a tab, and the
 * bytes the reference writes, with CR as \r and LF as \n.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned long long U64;
static int g_utilDisplayLevel;
static int g_displayLevel;
typedef struct { double value; int precision; const char* suffix; } HRS;

static HRS UTIL_makeHumanReadableSize(U64 size)
{
    HRS hrs;
    if (g_utilDisplayLevel > 3) {
        if (size >= (1ull << 53)) {
            hrs.value = (double)size / (1ull << 20);
            hrs.suffix = " MiB";
            hrs.precision = 2;
        } else {
            hrs.value = (double)size;
            hrs.suffix = " B";
            hrs.precision = 0;
        }
    } else {
        if (size >= (1ull << 60)) {
            hrs.value = (double)size / (1ull << 60); hrs.suffix = " EiB";
        } else if (size >= (1ull << 50)) {
            hrs.value = (double)size / (1ull << 50); hrs.suffix = " PiB";
        } else if (size >= (1ull << 40)) {
            hrs.value = (double)size / (1ull << 40); hrs.suffix = " TiB";
        } else if (size >= (1ull << 30)) {
            hrs.value = (double)size / (1ull << 30); hrs.suffix = " GiB";
        } else if (size >= (1ull << 20)) {
            hrs.value = (double)size / (1ull << 20); hrs.suffix = " MiB";
        } else if (size >= (1ull << 10)) {
            hrs.value = (double)size / (1ull << 10); hrs.suffix = " KiB";
        } else {
            hrs.value = (double)size; hrs.suffix = " B";
        }
        if (hrs.value >= 100 || (U64)hrs.value == size) hrs.precision = 0;
        else if (hrs.value >= 10) hrs.precision = 1;
        else if (hrs.value > 1) hrs.precision = 2;
        else hrs.precision = 3;
    }
    return hrs;
}

static void show(const char* buf)
{
    for (; *buf; buf++) {
        if (*buf == '\r') fputs("\\r", stdout);
        else if (*buf == '\n') fputs("\\n", stdout);
        else putchar(*buf);
    }
    putchar('\n');
}

#define DISPLAY_PROGRESS(...) { p += sprintf(p, __VA_ARGS__); }

int main(void)
{
    char line[1024];
    while (fgets(line, sizeof line, stdin)) {
        char kind[32], name[256];
        char out[4096]; char* p = out;
        unsigned dl, nbFilesTotal, idx;
        line[strcspn(line, "\n")] = 0;
        if (sscanf(line, "%31s", kind) != 1) continue;
        printf("%s\t", line);
        if (!strcmp(kind, "compress")) {
            long long fileSizeIn; int compressionLevel;
            U64 ingested, consumed, produced;
            sscanf(line, "%*s %u %u %u %255s %lld %d %llu %llu %llu", &dl, &nbFilesTotal, &idx, name,
                   &fileSizeIn, &compressionLevel, &ingested, &consumed, &produced);
            g_displayLevel = g_utilDisplayLevel = (int)dl;
            const char* srcFileName = name;
            U64 fileSize = (U64)fileSizeIn;
            HRS file_hrs = UTIL_makeHumanReadableSize(fileSize);
            double const cShare = (double)produced / (double)(consumed + !consumed) * 100;
            HRS buffered_hrs = UTIL_makeHumanReadableSize(ingested - consumed);
            HRS consumed_hrs = UTIL_makeHumanReadableSize(consumed);
            HRS produced_hrs = UTIL_makeHumanReadableSize(produced);
            DISPLAY_PROGRESS("\r%79s\r", "");
            if (g_displayLevel >= 3) {
                DISPLAY_PROGRESS(
                        "(L%i) Buffered:%5.*f%s - Consumed:%5.*f%s - Compressed:%5.*f%s => %.2f%% ",
                        compressionLevel,
                        buffered_hrs.precision, buffered_hrs.value, buffered_hrs.suffix,
                        consumed_hrs.precision, consumed_hrs.value, consumed_hrs.suffix,
                        produced_hrs.precision, produced_hrs.value, produced_hrs.suffix,
                        cShare );
            } else {
                if (nbFilesTotal > 1) {
                    size_t srcFileNameSize = strlen(srcFileName);
                    if (srcFileNameSize > 18) {
                        const char* truncatedSrcFileName = srcFileName + srcFileNameSize - 15;
                        DISPLAY_PROGRESS("Compress: %u/%u files. Current: ...%s ",
                                    idx+1, nbFilesTotal, truncatedSrcFileName);
                    } else {
                        DISPLAY_PROGRESS("Compress: %u/%u files. Current: %*s ",
                                    idx+1, nbFilesTotal, (int)(18-srcFileNameSize), srcFileName);
                    }
                }
                DISPLAY_PROGRESS("Read:%6.*f%4s ", consumed_hrs.precision, consumed_hrs.value, consumed_hrs.suffix);
                if (fileSize != (U64)-1)
                    DISPLAY_PROGRESS("/%6.*f%4s", file_hrs.precision, file_hrs.value, file_hrs.suffix);
                DISPLAY_PROGRESS(" ==> %2.f%%", cShare);
            }
        } else {
            U64 bytes;
            sscanf(line, "%*s %u %u %u %255s %llu", &dl, &nbFilesTotal, &idx, name, &bytes);
            g_displayLevel = g_utilDisplayLevel = (int)dl;
            const char* srcFName20 = name;
            size_t srcFileLength = strlen(name);
            if ((srcFileLength>20) && (g_displayLevel<3)) srcFName20 += srcFileLength-20;
            HRS hrs = UTIL_makeHumanReadableSize(bytes);
            if (nbFilesTotal > 1) {
                DISPLAY_PROGRESS(
                        "\rDecompress: %2u/%2u files. Current: %s : %.*f%s...    ",
                        idx+1, nbFilesTotal, srcFName20, hrs.precision, hrs.value, hrs.suffix);
            } else {
                DISPLAY_PROGRESS("\r%-20.20s : %.*f%s...     ",
                        srcFName20, hrs.precision, hrs.value, hrs.suffix);
            }
        }
        show(out);
    }
    return 0;
}
