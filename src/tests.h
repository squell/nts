#ifndef NTS_STANDALONE_TEST
#    include "tests.h"
#    include "timesyncd-conf.h"
#else
#    define _GNU_SOURCE 1
#    include <assert.h>
#    include <stdio.h>
#    include <string.h>
#    define HAVE_OPENSSL 1
#    define assert_se assert
#    define TEST(name) static void test_##name(void)
#    define DEFINE_TEST_MAIN(_ignore) int main(void) { \
        test_nts_encoding(); \
        test_nts_decoding(); \
        test_ntp_field_encoding(); \
        test_ntp_field_decoding(); \
        test_crypto(); \
        test_keysize(); \
        return 0; \
     } int _placeholder
#endif
