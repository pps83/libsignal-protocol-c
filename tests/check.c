#include "check.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define CK_MAX_TESTS 64
#define CK_MAX_TCASES 8

struct TCase {
    const char *name;
    SFun setup;
    SFun teardown;
    TFun tests[CK_MAX_TESTS];
    const char *test_names[CK_MAX_TESTS];
    int test_count;
};

struct Suite {
    const char *name;
    TCase *tcases[CK_MAX_TCASES];
    int tcase_count;
};

struct SRunner {
    Suite *suite;
    int failed;
};

static void ck_print_failure(const char *file, int line, const char *message)
{
    fprintf(stderr, "%s:%d: %s\n", file, line, message);
}

void (*ck_failure_hook)(const char *file, int line, const char *message) = ck_print_failure;

static jmp_buf ck_test_end;
static int ck_test_running;

void ck_fail_test(const char *file, int line, const char *format, ...)
{
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    ck_failure_hook(file, line, message);
    if(ck_test_running) {
        longjmp(ck_test_end, 1);
    }
    abort();
}

Suite *suite_create(const char *name)
{
    Suite *suite = calloc(1, sizeof(Suite));
    suite->name = name;
    return suite;
}

TCase *tcase_create(const char *name)
{
    TCase *tcase = calloc(1, sizeof(TCase));
    tcase->name = name;
    return tcase;
}

void tcase_add_checked_fixture(TCase *tcase, SFun setup, SFun teardown)
{
    tcase->setup = setup;
    tcase->teardown = teardown;
}

void tcase_add_test_named(TCase *tcase, TFun test, const char *name)
{
    if(tcase->test_count == CK_MAX_TESTS) {
        abort();
    }
    tcase->tests[tcase->test_count] = test;
    tcase->test_names[tcase->test_count] = name;
    tcase->test_count++;
}

void suite_add_tcase(Suite *suite, TCase *tcase)
{
    if(suite->tcase_count == CK_MAX_TCASES) {
        abort();
    }
    suite->tcases[suite->tcase_count++] = tcase;
}

SRunner *srunner_create(Suite *suite)
{
    SRunner *runner = calloc(1, sizeof(SRunner));
    runner->suite = suite;
    return runner;
}

void srunner_run_all(SRunner *runner, int mode)
{
    int i;
    int j;
    for(i = 0; i < runner->suite->tcase_count; i++) {
        TCase *tcase = runner->suite->tcases[i];
        for(j = 0; j < tcase->test_count; j++) {
            if(mode >= CK_VERBOSE) {
                fprintf(stderr, "%s: %s\n", runner->suite->name, tcase->test_names[j]);
            }
            if(tcase->setup) {
                tcase->setup();
            }
            ck_test_running = 1;
            if(setjmp(ck_test_end) == 0) {
                tcase->tests[j](0);
            }
            else {
                runner->failed++;
            }
            ck_test_running = 0;
            if(tcase->teardown) {
                tcase->teardown();
            }
        }
    }
}

int srunner_ntests_failed(SRunner *runner)
{
    return runner->failed;
}

void srunner_free(SRunner *runner)
{
    int i;
    for(i = 0; i < runner->suite->tcase_count; i++) {
        free(runner->suite->tcases[i]);
    }
    free(runner->suite);
    free(runner);
}
