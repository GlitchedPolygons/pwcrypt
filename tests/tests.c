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

#define TEST_INIT pwcrypt_disable_fprintf()

#include <acutest.h>

/* A test case that does nothing and succeeds. */
static void null_test_success()
{
    TEST_CHECK(1);
}

static void pwcrypt_fprintf_enables_and_disables_correctly()
{
    pwcrypt_disable_fprintf();
    TEST_CHECK(!pwcrypt_is_fprintf_enabled());
    TEST_CHECK(pwcrypt_fprintf_fptr != &fprintf);

    pwcrypt_enable_fprintf();
    TEST_CHECK(pwcrypt_is_fprintf_enabled());
    TEST_CHECK(pwcrypt_fprintf_fptr == &fprintf);

    pwcrypt_disable_fprintf();
}

static void pwcrypt_printvoid_returns_zero()
{
    TEST_CHECK(0 == pwcrypt_printvoid(stderr, "void", 4));
}

static void pw_strength_enforcing()
{
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"test", 4) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"Test12", 6) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"Tes1.", 4) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"TESTTESTTEST", 12) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"TEST13.,test", 12) == 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"TeS3.", 4) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"TESTTEST33333.#,", 16) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"testtest33333.#,", 16) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"testTEST33333333", 16) != 0);
    TEST_CHECK(pwcrypt_assess_password_strength((uint8_t*)"testTEST.,.###..", 16) != 0);
}

static void encrypt_and_decrypt_aes256_gcm_string_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 1, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_chachapoly_string_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 1, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_aes256_gcm_string_nocompression_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_chachapoly_string_nocompression_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_aes256_gcm_string_nobase64_success()
{
    uint8_t* out = NULL;
    size_t out_length = 0;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 1, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out, &out_length, 0);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_chachapoly_string_nobase64_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 1, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_aes256_gcm_string_nocompression_nobase64_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_chachapoly_string_nocompression_nobase64_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, NULL);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_with_invalid_params_fails()
{
    int r = 0;
    char* out = NULL;

    r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 0, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt(NULL, 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 0, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out);
    TEST_CHECK(r != 0);

    r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, NULL, 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, NULL);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, 200, &out);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    free(out);
}

static void decrypt_with_invalid_params_fails()
{
    char* out = NULL;
    int r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out);

    TEST_ASSERT(r == 0);

    char* decrypted = NULL;

    r = pwcrypt_decrypt(NULL, strlen(out), "Special Password for decrypting! 1337...", 40, &decrypted);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt(out, 0, "Special Password for decrypting! 1337...", 40, &decrypted);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt(out, strlen(out), NULL, 32, &decrypted);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt(out, strlen(out), "Special Password for decrypting! 1337...", 40, NULL);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    free(out);
    free(decrypted);
}

static void decrypt_invalid_ciphertext_fails()
{
    char* out = NULL;
    int r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out);

    TEST_ASSERT(r == 0);

    char* decrypted = NULL;

    r = pwcrypt_decrypt("TEST STRING THAT IS JUST NOT BASE64-encoded", 43, "Special Password for decrypting! 1337...", 40, &decrypted);
    TEST_CHECK(r != 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_with_wrong_PW_fails()
{
    char* out = NULL;
    int r = pwcrypt_encrypt("Lorem ipsum dolor sick fuck amend something something...........", 64, "Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, PWCRYPT_ALGO_ID_AES256_GCM, &out);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp(out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    char* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen(out), "WRONG WRONG WRONG password... just very extremely wrong!!!   420", 64, &decrypted);

    TEST_CHECK(decrypted == NULL);
    TEST_CHECK(r != 0);

    free(out);
    free(decrypted);
}

// --------------------------------------------------------------------------------------------------------------

TEST_LIST = {
    //
    { "nulltest", null_test_success }, //
    { "pwcrypt_fprintf_enables_and_disables_correctly", pwcrypt_fprintf_enables_and_disables_correctly }, //
    { "pwcrypt_printvoid_returns_zero", pwcrypt_printvoid_returns_zero }, //
    { "pw_strength_enforcing", pw_strength_enforcing }, //
    { "encrypt_and_decrypt_aes256_gcm_string_success", encrypt_and_decrypt_aes256_gcm_string_success }, //
    { "encrypt_and_decrypt_chachapoly_string_success", encrypt_and_decrypt_chachapoly_string_success }, //
    { "encrypt_with_invalid_params_fails", encrypt_with_invalid_params_fails }, //
    { "decrypt_with_invalid_params_fails", decrypt_with_invalid_params_fails }, //
    { "decrypt_invalid_ciphertext_fails", decrypt_invalid_ciphertext_fails }, //
    { "encrypt_and_decrypt_with_wrong_PW_fails", encrypt_and_decrypt_with_wrong_PW_fails }, //
    //
    // ----------------------------------------------------------------------------------------------------------
    //
    { NULL, NULL } //
};
