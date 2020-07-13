/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include <pwcrypt.h>
#include <acutest.h>

/* A test case that does nothing and succeeds. */
static void null_test_success()
{
    TEST_CHECK(1);
}

static void pw_strength_enforcing()
{
    TEST_CHECK(pwcrypt_assess_password_strength("test", 4) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("Test12", 6) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("Tes1.", 4) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("TESTTESTTEST", 12) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("TEST13.,test", 12) == 0);
    TEST_CHECK(pwcrypt_assess_password_strength("TeS3.", 4) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("TESTTEST33333.#,", 16) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("testtest33333.#,", 16) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("testTEST33333333", 16) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength("testTEST.,.###..", 16) != 0);
}

static void encrypt_and_decrypt_string_success()
{
    char* out = NULL;
    int r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, PWCRYPT_ARGON2_T_COST, PWCRYPT_ARGON2_M_COST, 2, &out);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp(out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    char* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen(out), "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp(decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

// --------------------------------------------------------------------------------------------------------------

TEST_LIST = {
    //
    { "nulltest", null_test_success }, //
    { "pw_strength_enforcing", pw_strength_enforcing }, //
    { "encrypt_and_decrypt_string_success", encrypt_and_decrypt_string_success }, //
    //
    // ----------------------------------------------------------------------------------------------------------
    //
    { NULL, NULL } //
};
