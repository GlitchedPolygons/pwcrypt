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

#define TEST_PW "TestPwcrypt_732657"

#define TEST_CIPHERTEXT_V_4_3_1 "AAABpgAAAAAAAAAIAAAAAQAAABMAAAAQAAEAAAAAAAJhSMCG3q6fuTaTkWoj6etsPK1OrD2S/OVhm0ut6wP2Yyia1beSNLjwaBq7bSXVA7A1sNMnAAylt+Pq5X/GjF9GEua2MJp/9jMtYpdcSRBwR9LscmEx1Dl5jVLxyDU2A6o5NPzFrg3cMfYQEZyrgOQ02q5p1R85AQc9OVEYsYIqa0S5TFDpFDe43ysD4bpdk50HRQ36vy8tWfN25Fem3EuCoVf4/NgoPTrMNgeMCdYKcisQg8qba8cAFOkQ6IvijMjDUsb8hkJvXnKimEfPMnOM4dGgR1hvSj2gxTLRhxsmdmZR2txmRi09U+avO6B+kdW9gLFzhxTT8j3r1/0NLyCjttxOKs3JEdicjL4sajU0aqHz3iqgGtGak0PG9kPm5RnnVv2nSf0KrG0CcbsLmzGJmB0qUhk87t5KBL0FgCNTQpys6mik6jTRgeA6gmpCT5IENNvkeZVskKPw3S33YHitEWC3VI+zFWh9wDzUk/2PZHR65vQ+XKjSr8jwYugWdMNp+hoJH6ENo1ly/TXKZAkhOOkxE5A9I03Mbh0="

#define TEST_CIPHERTEXT_V_4_3_1_CHACHAPOLY "AAABpgAAAAEAAAAIAAAAAQAAABMAAAAQAAEAAAAAAAIpu+6G+jmgbIFGijKS7rq6vtx0WFyKrWiaVf0+lB0P4pmgyqMU0SIoJSy/97/R+BOWHGjb0bqHGUcgv9r//6N/btKPLbaZQVBtayOZEE1uMR3KutXkxA0xOXjsqz4sItkCAFgkMG5q05imwTbf/JYJUfjx2mRniNK2jg2VzT3fAlSMvyLHqRRSFHstmLDwr3D1jkfacbAYCcr5w/lc3fr9CAwBNelsGYkaVlWL6j/l4sgFlbNePg/J9AV/rIiD/sgkHa4BwECVrQj2XQwotEK+SD0HiEADV4/7FqolhDFYhi0BuMIkMG7AybU8gVrP2duqtwcghfu4iG9OnVSN1KAfxL0C7UZFhzxGj7jF3kJzCxBjMwIE/l6OYSz9TU7IUhEBg0836DcQleOZVmdaOb53mUfPGntMwfDZqufqujFzTDTntC1cyU+rFCwHdvLZBlVSe1xuWC3tpPV/MkNht5e5A8l8XDNfDxx4yDE53fbGUPJ+dSypbheT3SdI7Fqd1230OsiXvu2/jPeG5GDvpPwMaqe+wfceChepzIs="

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

static void test_pwcrypt_memcmp()
{
    const uint8_t* s1 = "Lorem ipsum dolor sick fuck amend something something...";
    const uint8_t* s2 = "Not the same string as the one above";
    const uint8_t* s3 = "Lorem ipsum dolor sick fuck amend something something...";

    TEST_CHECK(pwcrypt_memcmp(s1,s3, 56) == 0);
    TEST_CHECK(pwcrypt_memcmp(s1,s3, 32) == 0);
    TEST_CHECK(pwcrypt_memcmp(s1,s2, 36) != 0);
    TEST_CHECK(pwcrypt_memcmp(s1,s2, 32) != 0);
    TEST_CHECK(pwcrypt_memcmp(s1,s2, 56) != 0);
}

static void encrypt_and_decrypt_aes256_gcm_string_success()
{
    uint8_t* out = NULL;
    size_t out_length = 0;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........", 256, 8, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, &out_length, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(out_length < 256); // Ensure compressor works!
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    size_t decrypted_length = 0;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, &decrypted_length);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(decrypted_length == 256);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void decrypt_old_ciphertext_aes256_gcm_string_success()
{
    uint8_t* decrypted = NULL;
    size_t decrypted_length = 0;
    int r = pwcrypt_decrypt(TEST_CIPHERTEXT_V_4_3_1, strlen((char*)TEST_CIPHERTEXT_V_4_3_1), (uint8_t*)TEST_PW, strlen((char*)TEST_PW), &decrypted, &decrypted_length);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);

    if (r == 0)
    {
        free(decrypted);
    }
}

static void decrypt_old_ciphertext_chachapoly_string_success()
{
    uint8_t* decrypted = NULL;
    size_t decrypted_length = 0;
    int r = pwcrypt_decrypt(TEST_CIPHERTEXT_V_4_3_1_CHACHAPOLY, strlen((char*)TEST_CIPHERTEXT_V_4_3_1_CHACHAPOLY), (uint8_t*)TEST_PW, strlen((char*)TEST_PW), &decrypted, &decrypted_length);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);

    if (r == 0)
    {
        free(decrypted);
    }
}

static void encrypt_and_decrypt_aes256_gcm_file_success()
{
    char tmp_in_file[256] = { 0x00 };
    char tmp_out_file[256] = { 0x00 };
    char tmp_dec_file[256] = { 0x00 };

    pwcrypt_get_temp_filepath(tmp_in_file);
    pwcrypt_get_temp_filepath(tmp_out_file);
    pwcrypt_get_temp_filepath(tmp_dec_file);

    FILE* tmp_in_file_fp = fopen(tmp_in_file, "wb");
    fwrite("TEST STRING HERE !!!", 1, 20, tmp_in_file_fp);
    fclose(tmp_in_file_fp);

    int r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) != pwcrypt_get_filesize(tmp_out_file));

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) == pwcrypt_get_filesize(tmp_dec_file));

    remove(tmp_in_file);
    remove(tmp_out_file);
    remove(tmp_dec_file);
}

static void encrypt_and_decrypt_chachapoly_file_success()
{
    char tmp_in_file[256] = { 0x00 };
    char tmp_out_file[256] = { 0x00 };
    char tmp_dec_file[256] = { 0x00 };

    pwcrypt_get_temp_filepath(tmp_in_file);
    pwcrypt_get_temp_filepath(tmp_out_file);
    pwcrypt_get_temp_filepath(tmp_dec_file);

    FILE* tmp_in_file_fp = fopen(tmp_in_file, "wb");
    fwrite("TEST STRING HERE !!!", 1, 20, tmp_in_file_fp);
    fclose(tmp_in_file_fp);

    int r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 1,  tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) != pwcrypt_get_filesize(tmp_out_file));

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) == pwcrypt_get_filesize(tmp_dec_file));

    remove(tmp_in_file);
    remove(tmp_out_file);
    remove(tmp_dec_file);
}

static void valgrind_test()
{
    char tmp_in_file[256] = { 0x00 };
    char tmp_out_file[256] = { 0x00 };
    char tmp_dec_file[256] = { 0x00 };

    pwcrypt_get_temp_filepath(tmp_in_file);
    pwcrypt_get_temp_filepath(tmp_out_file);
    pwcrypt_get_temp_filepath(tmp_dec_file);

    FILE* tmp_in_file_fp = fopen(tmp_in_file, "wb");
    fwrite("TEST STRING HERE !!!", 1, 20, tmp_in_file_fp);
    fclose(tmp_in_file_fp);

    int r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) != pwcrypt_get_filesize(tmp_out_file));

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) == pwcrypt_get_filesize(tmp_dec_file));

    remove(tmp_in_file);
    remove(tmp_out_file);
    remove(tmp_dec_file);
}

static void encrypt_and_decrypt_aes256_gcm_file_wrong_pw_fail()
{
    char tmp_in_file[256] = { 0x00 };
    char tmp_out_file[256] = { 0x00 };
    char tmp_dec_file[256] = { 0x00 };

    pwcrypt_get_temp_filepath(tmp_in_file);
    pwcrypt_get_temp_filepath(tmp_out_file);
    pwcrypt_get_temp_filepath(tmp_dec_file);

    FILE* tmp_in_file_fp = fopen(tmp_in_file, "wb");
    fwrite("TEST STRING HERE !!!", 1, 20, tmp_in_file_fp);
    fclose(tmp_in_file_fp);

    int r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) != pwcrypt_get_filesize(tmp_out_file));

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), (uint8_t*)"WRONG Password 111 ^^ ~ ?  ¨", 28, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == PWCRYPT_ERROR_DECRYPTION_FAILURE);

    remove(tmp_in_file);
    remove(tmp_out_file);
    remove(tmp_dec_file);
}

static void encrypt_and_decrypt_chachapoly_file_wrong_pw_fail()
{
    char tmp_in_file[256] = { 0x00 };
    char tmp_out_file[256] = { 0x00 };
    char tmp_dec_file[256] = { 0x00 };

    pwcrypt_get_temp_filepath(tmp_in_file);
    pwcrypt_get_temp_filepath(tmp_out_file);
    pwcrypt_get_temp_filepath(tmp_dec_file);

    FILE* tmp_in_file_fp = fopen(tmp_in_file, "wb");
    fwrite("TEST STRING HERE !!!", 1, 20, tmp_in_file_fp);
    fclose(tmp_in_file_fp);

    int r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 1,  tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == 0);
    TEST_CHECK(pwcrypt_get_filesize(tmp_in_file) != pwcrypt_get_filesize(tmp_out_file));

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), (uint8_t*)"WRONG Password 111 ^^ ~ ?  ¨", 28, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == PWCRYPT_ERROR_DECRYPTION_FAILURE);

    remove(tmp_in_file);
    remove(tmp_out_file);
    remove(tmp_dec_file);
}

static void encrypt_and_decrypt_file_wrong_args_fail()
{
    char tmp_in_file[256] = { 0x00 };
    char tmp_out_file[256] = { 0x00 };
    char tmp_dec_file[256] = { 0x00 };

    pwcrypt_get_temp_filepath(tmp_in_file);
    pwcrypt_get_temp_filepath(tmp_out_file);
    pwcrypt_get_temp_filepath(tmp_dec_file);

    int r = pwcrypt_encrypt_file(NULL, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Weak Pw", 7, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file));
    
    TEST_CHECK(r != 0);

    r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file) - 3, 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, NULL, 27, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 0,  NULL, strlen(tmp_out_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt_file(tmp_in_file, strlen(tmp_in_file), 6, (uint8_t*)"Test Password 456 ^^ ~ ?  ¨", 27, 2, 16, 1, 0, tmp_out_file, strlen(tmp_out_file) - 3);

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt_file(NULL, strlen(tmp_out_file), (uint8_t*)"WRONG Password 111 ^^ ~ ?  ¨", 28, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file) - 3, (uint8_t*)"WRONG Password 111 ^^ ~ ?  ¨", 28, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), NULL, 28, tmp_dec_file, strlen(tmp_dec_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), (uint8_t*)"WRONG Password 111 ^^ ~ ?  ¨", 28, NULL, strlen(tmp_dec_file));

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt_file(tmp_out_file, strlen(tmp_out_file), (uint8_t*)"WRONG Password 111 ^^ ~ ?  ¨", 28, tmp_dec_file, strlen(tmp_dec_file) - 3);

    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);
}

static void encrypt_and_decrypt_chachapoly_string_success()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, NULL, 1);

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
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);

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
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, NULL, 1);

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
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 1, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, &out_length, 0);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    size_t decrypted_length = 0;
    r = pwcrypt_decrypt(out, out_length, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, &decrypted_length);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(decrypted_length == 64);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_chachapoly_string_nobase64_success()
{
    uint8_t* out = NULL;
    size_t out_length = 0;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, &out_length, 0);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    size_t decrypted_length = 0;
    r = pwcrypt_decrypt(out, out_length, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, &decrypted_length);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(decrypted_length == 64);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_aes256_gcm_string_nocompression_nobase64_success()
{
    uint8_t* out = NULL;
    size_t out_length = 0;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, &out_length, 0);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    size_t decrypted_length = 0;
    r = pwcrypt_decrypt(out, out_length, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, &decrypted_length);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(decrypted_length == 64);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_chachapoly_string_nocompression_nobase64_success()
{
    uint8_t* out = NULL;
    size_t out_length = 0;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 0, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_CHACHA20_POLY1305, &out, &out_length, 0);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    size_t decrypted_length = 0;
    r = pwcrypt_decrypt(out, out_length, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, &decrypted, &decrypted_length);

    TEST_CHECK(decrypted != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(decrypted_length == 64);
    TEST_CHECK(strcmp((char*)decrypted, "Lorem ipsum dolor sick fuck amend something something...........") == 0);

    (void)pwcrypt_get_version_nr_string();

    pwcrypt_free(out);
    pwcrypt_free(decrypted);
}

static void encrypt_with_invalid_params_fails()
{
    int r = 0;
    uint8_t* out = NULL;

    r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 0, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt(NULL, 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 0, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);
    TEST_CHECK(r != 0);

    r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, NULL, 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, NULL, NULL, 1);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 0, 0, 0, 200, &out, NULL, 1);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    free(out);
}

static void decrypt_with_invalid_params_fails()
{
    uint8_t* out = NULL;
    size_t out_length = 0;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 7, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, &out_length, 1);

    TEST_ASSERT(r == 0);

    uint8_t* decrypted = NULL;

    r = pwcrypt_decrypt(NULL, out_length, (uint8_t*)"Special Password for decrypting! 1337...", 40, &decrypted, NULL);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt(out, 0, (uint8_t*)"Special Password for decrypting! 1337...", 40, &decrypted, NULL);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt(out, out_length, NULL, 32, &decrypted, NULL);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    r = pwcrypt_decrypt(out, out_length, (uint8_t*)"Special Password for decrypting! 1337...", 40, NULL, NULL);
    TEST_CHECK(r == PWCRYPT_ERROR_INVALID_ARGS);

    free(out);
    free(decrypted);
}

static void decrypt_invalid_ciphertext_fails()
{
    uint8_t* out = NULL;
    size_t out_length = 0;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, &out_length, 1);

    TEST_ASSERT(r == 0);

    uint8_t* decrypted = NULL;

    r = pwcrypt_decrypt((uint8_t*)"TEST STRING THAT IS JUST NOT BASE64-encoded", 43, (uint8_t*)"Special Password for decrypting! 1337...", 40, &decrypted, NULL);
    TEST_CHECK(r != 0);

    free(out);
    free(decrypted);
}

static void encrypt_and_decrypt_with_wrong_PW_fails()
{
    uint8_t* out = NULL;
    int r = pwcrypt_encrypt((uint8_t*)"Lorem ipsum dolor sick fuck amend something something...........", 64, 6, (uint8_t*)"Extremely safe password WITH UPPER CASE LETTERS, $pec1aL $ymbOLz 'n' stuff ;D", 77, 2, 16, 1, PWCRYPT_ALGO_ID_AES256_GCM, &out, NULL, 1);

    TEST_CHECK(out != NULL);
    TEST_CHECK(r == 0);
    TEST_CHECK(strcmp((char*)out, "Lorem ipsum dolor sick fuck amend something something...........") != 0);

    uint8_t* decrypted = NULL;
    r = pwcrypt_decrypt(out, strlen((char*)out), (uint8_t*)"WRONG WRONG WRONG password... just very extremely wrong!!!   420", 64, &decrypted, NULL);

    TEST_CHECK(decrypted == NULL);
    TEST_CHECK(r != 0);

    free(out);
    free(decrypted);
}

// --------------------------------------------------------------------------------------------------------------

TEST_LIST = {
    //
 { "nulltest", null_test_success }, //
 { "test_pwcrypt_memcmp", test_pwcrypt_memcmp }, //
 { "pwcrypt_fprintf_enables_and_disables_correctly", pwcrypt_fprintf_enables_and_disables_correctly }, //
 { "pwcrypt_printvoid_returns_zero", pwcrypt_printvoid_returns_zero }, //
 { "pw_strength_enforcing", pw_strength_enforcing }, //
 { "encrypt_and_decrypt_aes256_gcm_string_success", encrypt_and_decrypt_aes256_gcm_string_success }, //
 { "encrypt_and_decrypt_aes256_gcm_string_nobase64_success", encrypt_and_decrypt_aes256_gcm_string_nobase64_success }, //
 { "encrypt_and_decrypt_aes256_gcm_string_nocompression_success", encrypt_and_decrypt_aes256_gcm_string_nocompression_success }, //
 { "encrypt_and_decrypt_aes256_gcm_string_nocompression_nobase64_success", encrypt_and_decrypt_aes256_gcm_string_nocompression_nobase64_success }, //
 { "encrypt_and_decrypt_chachapoly_string_success", encrypt_and_decrypt_chachapoly_string_success }, //
 { "encrypt_and_decrypt_chachapoly_string_nobase64_success", encrypt_and_decrypt_chachapoly_string_nobase64_success }, //
 { "encrypt_and_decrypt_chachapoly_string_nocompression_success", encrypt_and_decrypt_chachapoly_string_nocompression_success }, //
 { "encrypt_and_decrypt_chachapoly_string_nocompression_nobase64_success", encrypt_and_decrypt_chachapoly_string_nocompression_nobase64_success }, //
 { "encrypt_with_invalid_params_fails", encrypt_with_invalid_params_fails }, //
 { "decrypt_with_invalid_params_fails", decrypt_with_invalid_params_fails }, //
 { "decrypt_invalid_ciphertext_fails", decrypt_invalid_ciphertext_fails }, //
 { "encrypt_and_decrypt_with_wrong_PW_fails", encrypt_and_decrypt_with_wrong_PW_fails }, //
 { "encrypt_and_decrypt_aes256_gcm_file_success", encrypt_and_decrypt_aes256_gcm_file_success }, //
 { "encrypt_and_decrypt_chachapoly_file_success", encrypt_and_decrypt_chachapoly_file_success }, //
 { "encrypt_and_decrypt_aes256_gcm_file_wrong_pw_fail", encrypt_and_decrypt_aes256_gcm_file_wrong_pw_fail }, //
 { "encrypt_and_decrypt_chachapoly_file_wrong_pw_fail", encrypt_and_decrypt_chachapoly_file_wrong_pw_fail }, //
 { "decrypt_old_ciphertext_aes256_gcm_string_success", decrypt_old_ciphertext_aes256_gcm_string_success }, //
 { "decrypt_old_ciphertext_chachapoly_string_success", decrypt_old_ciphertext_chachapoly_string_success }, //
 { "encrypt_and_decrypt_file_wrong_args_fail", encrypt_and_decrypt_file_wrong_args_fail }, //
    { "valgrind_test", valgrind_test }, //
    //
    // ----------------------------------------------------------------------------------------------------------
    //
    { NULL, NULL } //
};
