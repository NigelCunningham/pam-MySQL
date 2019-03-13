/**
 * PAM MySQL tests.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_make_scrambled_password_produces_expected_output() {
}

int main(void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_make_scrambled_password_produces_expected_output),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
