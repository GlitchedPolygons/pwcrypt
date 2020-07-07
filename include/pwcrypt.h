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

/**
 * Checks whether a given password is strong enough or not.
 * @param password Password string to check (does not need to be NUL-terminated; only \p password_length characters will be checked!).
 * @param password_length Length of the \p password string.
 * @return <c>0</c> if the password is OK; a non-zero error code if the password is too weak.
 */
int pwcrypt_assess_password_strength(const char* password, size_t password_length);

/**
 * Compresses an array of bytes using deflate.
 * @param data The data to compress.
 * @param data_length Length of the \p data array (how many bytes to compress).
 * @param buffer_size_kib The underlying buffer size to use (in KiB). Especially <c>inflate()</c> profits from a relatively large buffer aka. "chunk" size. A 256KiB buffer works great :)
 * @param level The level of compression <c>[0-9]</c>. Lower means faster, higher level means better compression (but slower). Default is <c>6</c>. If you pass a value that is out of the allowed range of <c>[0-9]</c>, <c>6</c> will be used!
 * @param out Pointer to an output buffer. This will be allocated on the heap ONLY on success: if something failed, this is left untouched! Needs to be freed manually by the caller.
 * @param out_length Where to write the output array's length into.
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
int pwcrypt_compress(const uint8_t* data, size_t data_length, size_t buffer_size_kib, int level, uint8_t** out, size_t* out_length);

/**
 * Decompresses a given set of deflated data using inflate.
 * @param data The compressed bytes to decompress.
 * @param data_length Length of the \p data array.
 * @param buffer_size_kib The underlying buffer size to use (in KiB). If available, a buffer size of 256KiB or more is recommended.
 * @param out Output buffer pointer: this will be allocated and filled with the decompressed data. In case of a failure it's left alone, so you only need to free it if decompression succeeds!
 * @param out_length Where to write the output array's length into.
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
int pwcrypt_decompress(const uint8_t* data, size_t data_length, size_t buffer_size_kib, uint8_t** out, size_t* out_length);

/**
 * TODO: write docs
 * @param text
 * @param text_length
 * @param password
 * @param password_length
 * @param argon2_cost_t
 * @param argon2_cost_m
 * @param argon2_parallelism
 * @param out
 * @return
 */
int pwcrypt_encrypt(const char* text, size_t text_length, const char* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, char** out);

/**
 * TODO: write docs
 * @param text
 * @param text_length
 * @param password
 * @param password_length
 * @param out
 * @return
 */
int pwcrypt_decrypt(const char* text, size_t text_length, const char* password, size_t password_length, char** out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PWCRYPT_H
