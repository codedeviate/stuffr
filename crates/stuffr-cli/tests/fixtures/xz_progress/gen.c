// SPDX-License-Identifier: 0BSD
//
// Renders XZ Utils 5.8.4's progress lines for a table of counters and
// clocks, with message.c's and util.c's own code: the progress_* field
// functions and uint64_to_nicestr below are copied verbatim from
// src/xz/message.c and src/xz/util.c (Lasse Collin, Jia Tan; 0BSD), as
// liblzma-sys 0.4.9 bundles them. Only the scaffolding (globals, main,
// the table) is new. The C locale has no thousands separator, so the
// FORMAT_THOUSAND_SEP branches are left out.
//
// Regenerate `table.txt` (see README.md):
//   cc -O0 -o gen gen.c && ./gen > table.txt

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

enum nicestr_unit { NICESTR_B, NICESTR_KIB, NICESTR_MIB, NICESTR_GIB, NICESTR_TIB };

static uint64_t expected_in_size;
static char bufs[4][128];

// ---- util.c ----

static void
my_snprintf(char **pos, size_t *left, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	const int len = vsnprintf(*pos, *left, fmt, ap);
	va_end(ap);
	if (len < 0 || (size_t)(len) >= *left) {
		*left = 0;
	} else {
		*pos += len;
		*left -= (size_t)(len);
	}
}

static const char *
uint64_to_nicestr(uint64_t value, enum nicestr_unit unit_min,
		enum nicestr_unit unit_max, bool always_also_bytes,
		uint32_t slot)
{
	enum nicestr_unit unit = NICESTR_B;
	char *pos = bufs[slot];
	size_t left = sizeof(bufs[slot]);

	if ((unit_min == NICESTR_B && value < 10000)
			|| unit_max == NICESTR_B) {
		my_snprintf(&pos, &left, "%u", (unsigned int)value);
	} else {
		double d = (double)(value);
		do {
			d /= 1024.0;
			++unit;
		} while (unit < unit_min || (d > 9999.9 && unit < unit_max));

		my_snprintf(&pos, &left, "%.1f", d);
	}

	static const char suffix[5][4] = { "B", "KiB", "MiB", "GiB", "TiB" };
	my_snprintf(&pos, &left, " %s", suffix[unit]);

	if (always_also_bytes && value >= 10000)
		snprintf(pos, left, " (%" PRIu64 " B)", value);

	return bufs[slot];
}

// ---- message.c ----

static const char *
progress_percentage(uint64_t in_pos)
{
	if (expected_in_size == 0 || in_pos > expected_in_size)
		return "--- %";
	double percentage = (double)(in_pos) / (double)(expected_in_size)
			* 99.9;
	static char buf[16];
	snprintf(buf, sizeof(buf), "%.1f %%", percentage);
	return buf;
}

static const char *
progress_sizes(uint64_t compressed_pos, uint64_t uncompressed_pos, bool final)
{
	static char buf[128];
	char *pos = buf;
	size_t left = sizeof(buf);
	const enum nicestr_unit unit_min = final ? NICESTR_B : NICESTR_MIB;
	my_snprintf(&pos, &left, "%s / %s",
			uint64_to_nicestr(compressed_pos,
				unit_min, NICESTR_TIB, false, 0),
			uint64_to_nicestr(uncompressed_pos,
				unit_min, NICESTR_TIB, false, 1));
	const double ratio = uncompressed_pos > 0
			? (double)(compressed_pos) / (double)(uncompressed_pos)
			: 16.0;
	if (ratio > 9.999)
		snprintf(pos, left, " > %.3f", 9.999);
	else
		snprintf(pos, left, " = %.3f", ratio);
	return buf;
}

static const char *
progress_speed(uint64_t uncompressed_pos, uint64_t elapsed)
{
	if (elapsed < 3000)
		return "";
	static const char unit[] = { 'K', 'M', 'G' };
	size_t unit_index = 0;
	double speed = (double)(uncompressed_pos)
			/ ((double)(elapsed) * (1024.0 / 1000.0));
	while (speed > 999.0) {
		speed /= 1024.0;
		if (++unit_index == ARRAY_SIZE(unit))
			return "";
	}
	static char buf[16];
	snprintf(buf, sizeof(buf), "%.*f %ciB/s",
			speed > 9.9 ? 0 : 1, speed, unit[unit_index]);
	return buf;
}

static const char *
progress_time(uint64_t mseconds)
{
	static char buf[sizeof("9999:59:59")];
	uint32_t seconds = (uint32_t)(mseconds / 1000);
	if (seconds == 0 || seconds > ((9999 * 60) + 59) * 60 + 59)
		return "";
	uint32_t minutes = seconds / 60;
	seconds %= 60;
	if (minutes >= 60) {
		const uint32_t hours = minutes / 60;
		minutes %= 60;
		snprintf(buf, sizeof(buf),
				"%" PRIu32 ":%02" PRIu32 ":%02" PRIu32,
				hours, minutes, seconds);
	} else {
		snprintf(buf, sizeof(buf), "%" PRIu32 ":%02" PRIu32,
				minutes, seconds);
	}
	return buf;
}

static const char *
progress_remaining(uint64_t in_pos, uint64_t elapsed)
{
	if (expected_in_size == 0 || in_pos > expected_in_size
			|| in_pos < (UINT64_C(1) << 19) || elapsed < 8000)
		return "";
	uint32_t remaining = (uint32_t)((double)(expected_in_size - in_pos)
			* ((double)(elapsed) / 1000.0) / (double)(in_pos));
	if (remaining < 1)
		remaining = 1;
	static char buf[sizeof("9 h 55 min")];
	if (remaining <= 10) {
		snprintf(buf, sizeof(buf), "%" PRIu32 " s", remaining);
	} else if (remaining <= 50) {
		remaining = (remaining + 4) / 5 * 5;
		snprintf(buf, sizeof(buf), "%" PRIu32 " s", remaining);
	} else if (remaining <= 590) {
		remaining = (remaining + 9) / 10 * 10;
		snprintf(buf, sizeof(buf), "%" PRIu32 " min %" PRIu32 " s",
				remaining / 60, remaining % 60);
	} else if (remaining <= 59 * 60) {
		remaining = (remaining + 59) / 60;
		snprintf(buf, sizeof(buf), "%" PRIu32 " min", remaining);
	} else if (remaining <= 9 * 3600 + 50 * 60) {
		remaining = (remaining + 599) / 600 * 10;
		snprintf(buf, sizeof(buf), "%" PRIu32 " h %" PRIu32 " min",
				remaining / 60, remaining % 60);
	} else if (remaining <= 23 * 3600) {
		remaining = (remaining + 3599) / 3600;
		snprintf(buf, sizeof(buf), "%" PRIu32 " h", remaining);
	} else if (remaining <= 9 * 24 * 3600 + 23 * 3600) {
		remaining = (remaining + 3599) / 3600;
		snprintf(buf, sizeof(buf), "%" PRIu32 " d %" PRIu32 " h",
				remaining / 24, remaining % 24);
	} else if (remaining <= 999 * 24 * 3600) {
		remaining = (remaining + 24 * 3600 - 1) / (24 * 3600);
		snprintf(buf, sizeof(buf), "%" PRIu32 " d", remaining);
	} else {
		return "";
	}
	return buf;
}

// ---- the table ----

// message_progress_update's line (the automatic indicator's, and the one
// a signal asks for).
static void
update(char *out, size_t n, uint64_t in_pos, uint64_t c, uint64_t u,
		uint64_t elapsed)
{
	const char *cols[5] = {
		progress_percentage(in_pos),
		progress_sizes(c, u, false),
		progress_speed(u, elapsed),
		progress_time(elapsed),
		progress_remaining(in_pos, elapsed),
	};
	snprintf(out, n, "\r %*s %*s   %*s %10s   %10s\r",
			6, cols[0], 35, cols[1], 9, cols[2], cols[3], cols[4]);
}

// progress_flush's line: `automatic` (stderr is a terminal) or not, for a
// file named "f".
static void
flush(char *out, size_t n, bool automatic, bool finished, uint64_t in_pos,
		uint64_t c, uint64_t u, uint64_t elapsed)
{
	if (automatic) {
		const char *cols[5] = {
			finished ? "100 %" : progress_percentage(in_pos),
			progress_sizes(c, u, true),
			progress_speed(u, elapsed),
			progress_time(elapsed),
			finished ? "" : progress_remaining(in_pos, elapsed),
		};
		snprintf(out, n, "\r %*s %*s   %*s %10s   %10s\n",
				6, cols[0], 35, cols[1], 9, cols[2],
				cols[3], cols[4]);
		return;
	}
	char *pos = out;
	size_t left = n;
	my_snprintf(&pos, &left, "%s: ", "f");
	if (!finished) {
		const char *percentage = progress_percentage(in_pos);
		if (percentage[0] != '-')
			my_snprintf(&pos, &left, "%s, ", percentage);
	}
	my_snprintf(&pos, &left, "%s", progress_sizes(c, u, true));
	const char *speed = progress_speed(u, elapsed);
	if (speed[0] != '\0')
		my_snprintf(&pos, &left, ", %s", speed);
	const char *elapsed_str = progress_time(elapsed);
	if (elapsed_str[0] != '\0')
		my_snprintf(&pos, &left, ", %s", elapsed_str);
	my_snprintf(&pos, &left, "\n");
}

static void
escaped(const char *s)
{
	for (; *s != '\0'; ++s) {
		if (*s == '\r')
			fputs("\\r", stdout);
		else if (*s == '\n')
			fputs("\\n", stdout);
		else if (*s == '\\')
			fputs("\\\\", stdout);
		else
			putchar(*s);
	}
}

int
main(void)
{
	const uint64_t MiB = UINT64_C(1) << 20;
	// expected_in_size, in_pos, compressed, uncompressed, elapsed (ms).
	static const uint64_t rows[][5] = {
		// 0 %, 50 %, 100 % of a known size, and past it.
		{ 10 * MiB, 0, 0, 0, 0 },
		{ 10 * MiB, 5 * MiB, 1234567, 5 * MiB, 500 },
		{ 10 * MiB, 10 * MiB, 2469134, 10 * MiB, 999 },
		{ 10 * MiB, 11 * MiB, 2469134, 11 * MiB, 1000 },
		// Unknown size (standard input).
		{ 0, 5 * MiB, 1234567, 5 * MiB, 500 },
		{ 0, 0, 32, 0, 0 },
		// 1:02 and 1:02:03, at each speed unit.
		{ 10 * MiB, 5 * MiB, 1234567, 5 * MiB, 62000 },
		{ 10 * MiB, 5 * MiB, 1234567, 5 * MiB, 3723000 },
		{ 0, 300, 60, 300, 62000 },
		{ 0, 30000, 6000, 30000, 3500 },
		{ 0, 3000000, 600000, 3000000, 3500 },
		{ 0, 30000000, 6000000, 30000000, 3500 },
		{ 0, 3000000000ULL, 600000000ULL, 3000000000ULL, 3500 },
		{ 0, 3000000000000ULL, 1, 3000000000000ULL, 3000 },
		{ 0, 3000000000000000ULL, 1, 3000000000000000ULL, 3000 },
		{ 0, 9 * 1024 * 3, 1, 9 * 1024 * 3, 3000 },
		{ 0, 10 * 1024 * 3, 1, 10 * 1024 * 3, 3000 },
		// The speed and time thresholds.
		{ 10 * MiB, 5 * MiB, 1234567, 5 * MiB, 2999 },
		{ 10 * MiB, 5 * MiB, 1234567, 5 * MiB, 3000 },
		{ 10 * MiB, 5 * MiB, 1234567, 5 * MiB, 7999 },
		{ 10 * MiB, 5 * MiB, 1234567, 5 * MiB, 8000 },
		// Remaining time in each precision.
		{ 100 * MiB, 99 * MiB, 1, 99 * MiB, 8000 },
		{ 100 * MiB, 80 * MiB, 1, 80 * MiB, 9000 },
		{ 100 * MiB, 20 * MiB, 1, 20 * MiB, 10000 },
		{ 100 * MiB, 2 * MiB, 1, 2 * MiB, 30000 },
		{ 100 * MiB, 20 * MiB, 1, 20 * MiB, 25000 },
		{ 2000 * MiB, 1 * MiB, 1, 1 * MiB, 20000 },
		{ 1000 * MiB, 1 * MiB, 1, 1 * MiB, 20000 },
		{ 10000 * MiB, 1 * MiB, 1, 1 * MiB, 20000 },
		{ 100000 * MiB, 1 * MiB, 1, 1 * MiB, 20000 },
		{ 1000000 * MiB, 1 * MiB, 1, 1 * MiB, 100000 },
		{ 1000000 * MiB, MiB / 2, 1, MiB / 2, 100000 },
		{ 1000000 * MiB, MiB / 2 - 1, 1, MiB / 2 - 1, 100000 },
		// Sizes: bytes, KiB, MiB, GiB and TiB; a ratio over 9.999.
		{ 0, 9999, 9999, 9999, 0 },
		{ 0, 10000, 10000, 10000, 0 },
		{ 0, 10239, 1, 10239, 0 },
		{ 0, 123456789012ULL, 98765432101ULL, 123456789012ULL, 0 },
		{ 0, 98765432101234ULL, 1, 98765432101234ULL, 0 },
		{ 0, 1, 200, 10, 0 },
		// Ridiculously long.
		{ 0, 1, 1, 1, UINT64_C(36000000000) },
	};
	char line[512];
	for (size_t i = 0; i < ARRAY_SIZE(rows); ++i) {
		const uint64_t *r = rows[i];
		expected_in_size = r[0];
		static const char *const kinds[] = {
			"update", "auto-finished", "auto-unfinished",
			"plain-finished", "plain-unfinished",
		};
		for (size_t k = 0; k < ARRAY_SIZE(kinds); ++k) {
			if (k == 0)
				update(line, sizeof(line), r[1], r[2], r[3], r[4]);
			else
				flush(line, sizeof(line), k <= 2, k % 2 == 1,
						r[1], r[2], r[3], r[4]);
			printf("%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
					"\t%" PRIu64 "\t%s\t", r[0], r[1], r[2],
					r[3], r[4], kinds[k]);
			escaped(line);
			putchar('\n');
		}
	}
	return 0;
}
