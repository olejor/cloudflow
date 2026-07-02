/* cf_log() output validity: every line written to stderr must be a single
 * valid JSON object containing at least ts/level/service/msg, with correct
 * escaping of quotes, backslashes, newlines, other control bytes, and
 * non-ASCII text.
 *
 * Mechanics: stderr is temporarily redirected (via dup2) to a temp file
 * while a batch of tricky strings is logged, one cf_log() call per string
 * (used as both the message and a "k" key/value pair). The raw expected
 * strings are separately NUL-separated into a second temp file. A small
 * generated Python script (python3 is a documented project dependency,
 * see 00-overview.md Convention 3) then parses every captured line with
 * the standard `json` module and checks the round-tripped values match
 * exactly. Everything is written under mkstemp() paths and cleaned up at
 * the end, so the test is hermetic and safe to run concurrently /
 * repeatedly. */

#include <CUnit/CUnit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cf_core_test.h"
#include "cf_log.h"

/* "control\x01\x02\x1fbytes" as raw bytes -- built as an explicit array
 * rather than C string-literal \x escapes because \x escapes are greedy
 * and would swallow the following 'b' (a valid hex digit) into the
 * escape. */
static const unsigned char control_bytes_raw[] = {
    'c', 'o', 'n', 't', 'r', 'o', 'l', 0x01, 0x02, 0x1f,
    'b', 'y', 't', 'e', 's', 0x00
};

/* "héllo — 日本語" (hello with an accented e, an
 * em-dash, then "Japanese" in kanji) encoded as raw UTF-8 bytes. */
static const unsigned char unicode_raw[] = {
    'h', 0xc3, 0xa9, 'l', 'l', 'o', ' ',
    0xe2, 0x80, 0x94, ' ',
    0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac, 0xe8, 0xaa, 0x9e,
    0x00
};

static const char *tricky_strings[] = {
    "simple",
    "has \"quotes\" inside",
    "back\\slash",
    "line1\nline2",
    "tab\there",
    (const char *)control_bytes_raw,
    (const char *)unicode_raw,
    "",
};

#define NUM_TRICKY (sizeof(tricky_strings) / sizeof(tricky_strings[0]))

static const char PYTHON_VALIDATOR[] =
    "import json\n"
    "import sys\n"
    "\n"
    "log_path, expected_path = sys.argv[1], sys.argv[2]\n"
    "\n"
    "with open(expected_path, 'rb') as f:\n"
    "    raw = f.read()\n"
    "expected = raw.split(b'\\0')\n"
    "if expected and expected[-1] == b'':\n"
    "    expected = expected[:-1]\n"
    "expected = [e.decode('utf-8') for e in expected]\n"
    "\n"
    "with open(log_path, 'r', encoding='utf-8') as f:\n"
    "    lines = [line for line in f if line.strip() != '']\n"
    "\n"
    "if len(lines) != len(expected):\n"
    "    print('line count mismatch: got %d want %d' % (len(lines), len(expected)), file=sys.stderr)\n"
    "    sys.exit(1)\n"
    "\n"
    "for i, line in enumerate(lines):\n"
    "    obj = json.loads(line)\n"
    "    for key in ('ts', 'level', 'service', 'msg'):\n"
    "        if key not in obj:\n"
    "            print('line %d missing key %s' % (i, key), file=sys.stderr)\n"
    "            sys.exit(1)\n"
    "    if obj['msg'] != expected[i]:\n"
    "        print('line %d msg mismatch: got %r want %r' % (i, obj['msg'], expected[i]), file=sys.stderr)\n"
    "        sys.exit(1)\n"
    "    if obj.get('k') != expected[i]:\n"
    "        print('line %d k mismatch: got %r want %r' % (i, obj.get('k'), expected[i]), file=sys.stderr)\n"
    "        sys.exit(1)\n"
    "    if obj['level'] != 'info':\n"
    "        print('line %d level mismatch: got %r' % (i, obj['level']), file=sys.stderr)\n"
    "        sys.exit(1)\n"
    "    if obj['service'] != 'cf_log_test':\n"
    "        print('line %d service mismatch: got %r' % (i, obj['service']), file=sys.stderr)\n"
    "        sys.exit(1)\n"
    "\n"
    "print('OK')\n"
    "sys.exit(0)\n";

static void test_cf_log_json_validity(void)
{
    char log_path[] = "/tmp/cf_log_test_log_XXXXXX";
    char expected_path[] = "/tmp/cf_log_test_expected_XXXXXX";
    char script_path[] = "/tmp/cf_log_test_validator_XXXXXX";
    int log_fd = -1;
    int expected_fd = -1;
    int script_fd = -1;
    int saved_stderr = -1;
    size_t i;
    char cmd[512];
    int rc;
    FILE *script_fp;

    log_fd = mkstemp(log_path);
    CU_ASSERT_FATAL(log_fd != -1);

    expected_fd = mkstemp(expected_path);
    CU_ASSERT_FATAL(expected_fd != -1);

    script_fd = mkstemp(script_path);
    CU_ASSERT_FATAL(script_fd != -1);

    /* Write the NUL-separated expected raw values. */
    for (i = 0; i < NUM_TRICKY; i++) {
        size_t len = strlen(tricky_strings[i]);

        CU_ASSERT_FATAL(write(expected_fd, tricky_strings[i], len) == (ssize_t)len);
        CU_ASSERT_FATAL(write(expected_fd, "", 1) == 1);
    }
    close(expected_fd);

    /* Write the validator script. */
    script_fp = fdopen(script_fd, "w");
    CU_ASSERT_FATAL(script_fp != NULL);
    fputs(PYTHON_VALIDATOR, script_fp);
    fclose(script_fp);

    /* Redirect stderr into the log file, log the tricky strings, restore
     * stderr. */
    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    CU_ASSERT_FATAL(saved_stderr != -1);
    CU_ASSERT_FATAL(dup2(log_fd, STDERR_FILENO) != -1);
    close(log_fd);

    cf_log_init("cf_log_test");
    for (i = 0; i < NUM_TRICKY; i++)
        cf_log(CF_LOG_INFO, tricky_strings[i], "k", tricky_strings[i], NULL);

    fflush(stderr);
    CU_ASSERT_FATAL(dup2(saved_stderr, STDERR_FILENO) != -1);
    close(saved_stderr);

    snprintf(cmd, sizeof(cmd), "python3 '%s' '%s' '%s'", script_path, log_path, expected_path);
    rc = system(cmd);

    CU_ASSERT_TRUE(rc != -1);
    CU_ASSERT_TRUE(WIFEXITED(rc) && WEXITSTATUS(rc) == 0);

    unlink(log_path);
    unlink(expected_path);
    unlink(script_path);
}

static void test_cf_log_line_is_single_line(void)
{
    /* A message containing a newline must not actually break the JSON
     * line in two -- cf_log() must escape it, not emit a raw newline. */
    char log_path[] = "/tmp/cf_log_test_oneline_XXXXXX";
    int log_fd;
    int saved_stderr;
    FILE *fp;
    char line[256];
    int lines = 0;

    log_fd = mkstemp(log_path);
    CU_ASSERT_FATAL(log_fd != -1);

    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    CU_ASSERT_FATAL(saved_stderr != -1);
    CU_ASSERT_FATAL(dup2(log_fd, STDERR_FILENO) != -1);
    close(log_fd);

    cf_log_init("cf_log_test");
    cf_log(CF_LOG_WARN, "multi\nline\nmessage", NULL);

    fflush(stderr);
    CU_ASSERT_FATAL(dup2(saved_stderr, STDERR_FILENO) != -1);
    close(saved_stderr);

    fp = fopen(log_path, "r");
    CU_ASSERT_FATAL(fp != NULL);
    while (fgets(line, sizeof(line), fp) != NULL)
        lines++;
    fclose(fp);
    unlink(log_path);

    CU_ASSERT_EQUAL(lines, 1);
}

int cf_log_register_suite(void)
{
    CU_pSuite suite = CU_add_suite("cf_log JSON validity", NULL, NULL);

    if (!suite)
        return -1;

    if (!CU_add_test(suite, "tricky strings round-trip through valid JSON", test_cf_log_json_validity))
        return -1;
    if (!CU_add_test(suite, "embedded newline stays on one output line", test_cf_log_line_is_single_line))
        return -1;

    return 0;
}
