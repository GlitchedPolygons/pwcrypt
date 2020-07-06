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

/**
 *  @file pwcrypt.h
 *  @author Raphael Beck
 *  @brief Encrypt and decrypt strings symmetrically using Argon2id key derivation + AES-256 (GCM).
 */

#ifndef PWCRYPT_H
#define PWCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#endif

static const char PWCRYPT_INVALID_ARGS_ERROR_MSG[] = "pwcrypt: Invalid arguments! Please run \"pwcrypt-- help\" to find out how to use this program.\n";

static const uint8_t EMPTY64[64] = {
    //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
};

#define PWCRYPT_Z_CHUNKSIZE (1024 * 256)

#define PWCRYPT_ARGON2_T_COST 4
#define PWCRYPT_ARGON2_M_COST (1024 * 128)
#define PWCRYPT_ARGON2_PARALLELISM 2

#define PWCRYPT_ERROR_INVALID_ARGS -1
#define PWCRYPT_ERROR_OOM 1000
#define PWCRYPT_ERROR_PW_TOO_WEAK 2000
#define PWCRYPT_ERROR_ARGON2_FAILURE 3000
#define PWCRYPT_ERROR_ENCRYPTION_FAILURE 4000
#define PWCRYPT_ERROR_DECRYPTION_FAILURE 5000
#define PWCRYPT_ERROR_BASE64_FAILURE 6000
#define PWCRYPT_ERROR_COMPRESSION_FAILURE 7000

#define PWCRYPT_MIN(x, y) (((x) < (y)) ? (x) : (y))
#define PWCRYPT_MAX(x, y) (((x) > (y)) ? (x) : (y))

/**
 * (Tries to) read from <c>/dev/urandom</c> (or Windows equivalent, yeah...) filling the given \p output_buffer with \p output_buffer_size random bytes.
 * @param output_buffer Where to write the random bytes into.
 * @param output_buffer_size How many random bytes to write into \p output_buffer
 */
static inline void dev_urandom(uint8_t* output_buffer, const size_t output_buffer_size)
{
    if (output_buffer != NULL && output_buffer_size > 0)
    {
#ifdef _WIN32
        BCryptGenRandom(NULL, output_buffer, output_buffer_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
        FILE* rnd = fopen("/dev/urandom", "r");
        if (rnd != NULL)
        {
            fread(output_buffer, sizeof(unsigned char), output_buffer_size, rnd);
            fclose(rnd);
        }
#endif
    }
}

int pwcrypt_assess_password_strength(const char* password, size_t password_length);

int pwcrypt_encrypt(const char* text, size_t text_length, const char* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, char** out);

int pwcrypt_decrypt(const char* text, size_t text_length, const char* password, size_t password_length, char** out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PWCRYPT_H
