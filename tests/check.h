#ifndef SIGNAL_TESTS_CHECK_H
#define SIGNAL_TESTS_CHECK_H

/*
 * The part of the Check unit test framework these tests use, so that they need no outside library: suites of test
 * cases with fixtures, run by srunner_run_all. A failed assertion reports through ck_failure_hook and ends its test
 * as Check's no-fork mode does, by a longjmp back to the runner.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CK_SILENT 0
#define CK_MINIMAL 1
#define CK_NORMAL 2
#define CK_VERBOSE 3

typedef void (*TFun)(int);
/* Unprototyped, as Check's: the tests' fixtures are declared as test_setup() */
typedef void (*SFun)();
typedef struct Suite Suite;
typedef struct TCase TCase;
typedef struct SRunner SRunner;

Suite *suite_create(const char *name);
TCase *tcase_create(const char *name);
void tcase_add_checked_fixture(TCase *tcase, SFun setup, SFun teardown);
void tcase_add_test_named(TCase *tcase, TFun test, const char *name);
void suite_add_tcase(Suite *suite, TCase *tcase);
SRunner *srunner_create(Suite *suite);
void srunner_run_all(SRunner *runner, int mode);
int srunner_ntests_failed(SRunner *runner);
void srunner_free(SRunner *runner);

/* Called for every failed assertion; the default prints it to stderr. A host's test runner may set its own. */
extern void (*ck_failure_hook)(const char *file, int line, const char *message);
/* Reports the failure and ends the running test. */
void ck_fail_test(const char *file, int line, const char *format, ...);

#ifdef __cplusplus
}
#endif

#define tcase_add_test(tcase, test) tcase_add_test_named(tcase, test, #test)
#define START_TEST(name) static void name(int _i) { (void)_i;
#define END_TEST }

#define ck_assert_msg(expr, ...) \
    do { \
        if(!(expr)) \
            ck_fail_test(__FILE__, __LINE__, "'" #expr "' failed: " __VA_ARGS__); \
    } while(0)
#define ck_assert(expr) ck_assert_msg(expr, "")
#define ck_abort() ck_fail_test(__FILE__, __LINE__, "aborted")
#define ck_abort_msg(...) ck_fail_test(__FILE__, __LINE__, __VA_ARGS__)
#define CK_COMPARE(type, format, x, op, y) \
    do { \
        type ck_x = (type)(x); \
        type ck_y = (type)(y); \
        if(!(ck_x op ck_y)) \
            ck_fail_test(__FILE__, __LINE__, "'%s' failed: " format " " #op " " format, #x " " #op " " #y, ck_x, ck_y); \
    } while(0)
#define ck_assert_int_eq(x, y) CK_COMPARE(intmax_t, "%jd", x, ==, y)
#define ck_assert_int_ne(x, y) CK_COMPARE(intmax_t, "%jd", x, !=, y)
#define ck_assert_int_ge(x, y) CK_COMPARE(intmax_t, "%jd", x, >=, y)
#define ck_assert_ptr_eq(x, y) CK_COMPARE(const void *, "%p", x, ==, y)
#define ck_assert_ptr_ne(x, y) CK_COMPARE(const void *, "%p", x, !=, y)
#define ck_assert_str_eq(x, y) ck_assert_msg(strcmp((x), (y)) == 0, "\"%s\" and \"%s\"", (x), (y))
#define ck_assert_str_ne(x, y) ck_assert_msg(strcmp((x), (y)) != 0, "\"%s\" and \"%s\"", (x), (y))

#endif /* SIGNAL_TESTS_CHECK_H */
