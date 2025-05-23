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

/* mmap() replacement for Windows
 *
 * Author: Mike Frysinger <vapier@gentoo.org>
 * Placed into the public domain
 */

/* References:
 * CreateFileMapping: http://msdn.microsoft.com/en-us/library/aa366537(VS.85).aspx
 * CloseHandle:       http://msdn.microsoft.com/en-us/library/ms724211(VS.85).aspx
 * MapViewOfFile:     http://msdn.microsoft.com/en-us/library/aa366761(VS.85).aspx
 * UnmapViewOfFile:   http://msdn.microsoft.com/en-us/library/aa366882(VS.85).aspx
 */

#include "pwcrypt.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <argon2.h>
#include <ccrush.h>
#include <assert.h>

#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/platform_util.h>

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#endif

#ifdef __BORLANDC__
#define _setmode setmode
#endif

static const uint32_t PWCRYPT_V = (uint32_t)PWCRYPT_VERSION;
static const uint32_t ARGON2_V = (uint32_t)ARGON2_VERSION_NUMBER;

static unsigned char pwcrypt_fprintf_enabled = 1;

unsigned char pwcrypt_is_fprintf_enabled()
{
    return pwcrypt_fprintf_enabled;
}

int (*pwcrypt_fprintf_fptr)(FILE* stream, const char* format, ...) = &fprintf;

void pwcrypt_enable_fprintf()
{
    pwcrypt_fprintf_enabled = 1;
    pwcrypt_fprintf_fptr = &fprintf;
}

void pwcrypt_disable_fprintf()
{
    pwcrypt_fprintf_enabled = 0;
    pwcrypt_fprintf_fptr = &pwcrypt_printvoid;
}

uint32_t pwcrypt_get_version_nr()
{
    return PWCRYPT_V;
}

uint32_t pwcrypt_get_argon2_version_nr()
{
    return ARGON2_V;
}

char* pwcrypt_get_version_nr_string()
{
    return PWCRYPT_VERSION_STR;
}

size_t pwcrypt_get_filesize(const char* filepath)
{
    size_t filesize = 0;

#ifdef _WIN32
    wchar_t* wpath = malloc(PWCRYPT_MAX_WIN_FILEPATH_LENGTH * sizeof(wchar_t));
    if (wpath == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Out of memory...");
        return 0;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, filepath, -1, wpath, PWCRYPT_MAX_WIN_FILEPATH_LENGTH) == 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Failed to convert the (allegedly) UTF-8 encoded filepath string to Windows Unicode-16 (using wchar_t[])");
        pwcrypt_free(wpath);
        return 0;
    }

    HANDLE f = CreateFileW(wpath, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Failure to open file for reading its size: %s", filepath);
        goto exit;
    }

    LARGE_INTEGER i;
    if (!GetFileSizeEx(f, &i))
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Failure to read file size: %s", filepath);
        goto exit;
    }

    filesize = (size_t)i.QuadPart;

exit:
    pwcrypt_free(wpath);
    CloseHandle(f);
    return filesize;
#else
    struct stat stbuf;
    if ((stat(filepath, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode)))
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Failure to assess filesize: %s (file not found?).", filepath);
        goto exit;
    }
    if (sizeof(stbuf.st_size) < 8)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: The current size of \"off_t\" (%d B) promises less than 64-bit file sizes, which means filesize representation in this implementation is limited to 2GB.", sizeof(stbuf.st_size));
    }
    filesize = (size_t)stbuf.st_size;
exit:
    mbedtls_platform_zeroize(&stbuf, sizeof(stbuf));
    return filesize;
#endif
}

void dev_urandom(uint8_t* output_buffer, const size_t output_buffer_size)
{
    if (output_buffer != NULL && output_buffer_size > 0)
    {
#ifdef _WIN32
        BCryptGenRandom(NULL, output_buffer, (ULONG)output_buffer_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
        FILE* rnd = pwcrypt_fopen("/dev/urandom", "r");
        if (rnd != NULL)
        {
            const size_t n = fread(output_buffer, sizeof(unsigned char), output_buffer_size, rnd);
            if (n != output_buffer_size)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Warning! Only %llu bytes out of %llu have been read from /dev/urandom\n", n, output_buffer_size);
            }
            fclose(rnd);
        }
#endif
    }
}

void pwcrypt_get_temp_filepath(char output_buffer[256])
{
    const time_t utc = time(NULL);

    uint8_t rnd[16];
    dev_urandom(rnd, sizeof(rnd));

    char rnds[16] = { 0x00 };
    char path[128] = { 0x00 };
    char file[128] = { 0x00 };
    const static char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_()";
    const size_t chars_size = sizeof(chars) - 1;

    for (int i = 0; i < sizeof(rnds) - 1; ++i)
    {
        rnds[i] = chars[(size_t)rnd[i] % chars_size];
    }

    snprintf(file, sizeof(file), "pwcrypt-%llu-%s", (unsigned long long)utc, rnds);

#ifdef _WIN32
    wchar_t wpath[128] = { 0x00 };
    const DWORD wpathlen = GetTempPathW(128, wpath);
    WideCharToMultiByte(CP_UTF8, 0, wpath, (int)wpathlen, path, 128, NULL, NULL);
#else
    snprintf(path, sizeof(path), "/var/tmp/");
#endif

    snprintf(output_buffer, 256, "%s%s", path, file);
}

void pwcrypt_free(void* ptr)
{
    free(ptr);
}

int pwcrypt_assess_password_strength(const uint8_t* password, const size_t password_length)
{
    if (password_length < 6)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Password too weak! Please use at least 6 characters, composed of at least 1 lowercase char, 1 uppercase char, 1 number and 1 special character!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    uint8_t strength = 0;

    for (int i = 0; i < password_length; ++i)
    {
        const uint8_t c = password[i];
        if (isupper(c))
        {
            strength |= 1 << 0;
            continue;
        }
        if (islower(c))
        {
            strength |= 1 << 1;
            continue;
        }
        if (isdigit(c))
        {
            strength |= 1 << 2;
            continue;
        }
        if (strchr(" !¨\"'()[]{}-_+*ç%&/='?^~¦@#°§¬|¢´\\.,;:$£€àèéöäü", c))
        {
            strength |= 1 << 3;
            continue;
        }
    }

    if (!(strength & 1 << 0))
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Please include at least 1 uppercase character in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    if (!(strength & 1 << 1))
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Please include at least 1 lowercase character in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    if (!(strength & 1 << 2))
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Please include at least 1 number in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    if (!(strength & 1 << 3))
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Please include at least 1 special character in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    return 0;
}

int pwcrypt_encrypt(const uint8_t* input, size_t input_length, uint32_t compress, const uint8_t* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, uint32_t algo, uint8_t** output, size_t* output_length, uint32_t output_base64)
{
    if (input == NULL || input_length == 0 || password == NULL || output == NULL)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    int r = pwcrypt_assess_password_strength(password, password_length);
    if (r != 0)
    {
        return (r);
    }

    int free_output_buffer = 1;

    uint8_t* ccrushed = NULL;
    size_t ccrushed_size = 0;

    uint8_t* output_buffer = NULL;
    size_t output_buffer_size = 0;

    uint8_t* output_buffer_base64 = NULL;
    size_t output_buffer_base64_size = 0;
    size_t output_buffer_base64_length = 0;

    size_t processed = 0;

    uint8_t key[32] = { 0x00 };

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    mbedtls_chachapoly_context chachapoly_ctx;
    mbedtls_chachapoly_init(&chachapoly_ctx);

    // [0 - 3]      (4B)   uint32_t:     Pwcrypt Version Number
    // [4 - 7]      (4B)   uint32_t:     Pwcrypt Algo ID
    // [8 - 11]     (4B)   uint32_t:     Pwcrypt Compression Enabled
    // [12 - 15]    (4B)   uint32_t:     Pwcrypt Base64 Encoded
    // [16 - 19]\   (4B)   uint32_t:     Argon2 Version Number
    // [20 - 23] |  (4B)   uint32_t:     Argon2 Cost T
    // [24 - 27] |  (4B)   uint32_t:     Argon2 Cost M
    // [28 - 31] |  (4B)   uint32_t:     Argon2 Parallelism
    // [32 - 63]/   (32B)  uint8_t[32]:  Argon2 Salt
    // [64 - 79]\   (16B)  uint8_t[16]:  AES-256 GCM IV (or 12B ChaCha20-Poly1305 IV, zero-padded)
    // [80 - 95] |  (16B)  uint8_t[16]:  AES-256 GCM Tag (or ChaCha20-Poly1305 Tag)
    // [96 - 99] |  (4B)   uint32_t:     Chunk length
    // [100 - n]/   (n B)  uint8_t[n]:   Chunk content (compressed + encrypted ciphertext)
    // [(n+1) - ...]                     (The last 4 sections make up a chunk; there can be as many chunks as needed)

    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);

    output_buffer_size = (64 + input_length + (input_length / 2));

    output_buffer = calloc(output_buffer_size, sizeof(uint8_t));
    if (output_buffer == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        r = PWCRYPT_ERROR_OOM;
        goto exit;
    }

    if (!argon2_cost_t)
        argon2_cost_t = PWCRYPT_ARGON2_T_COST;

    if (!argon2_cost_m)
        argon2_cost_m = PWCRYPT_ARGON2_M_COST;

    if (!argon2_parallelism)
        argon2_parallelism = PWCRYPT_ARGON2_PARALLELISM;

    if (output_base64)
        output_base64 = 1;

    uint32_t bigendian = htonl(pwcrypt_get_version_nr());
    memcpy(output_buffer, &bigendian, 4);

    bigendian = htonl(algo);
    memcpy(output_buffer + 4, &bigendian, 4);

    bigendian = htonl(compress);
    memcpy(output_buffer + 8, &bigendian, 4);

    bigendian = htonl(output_base64);
    memcpy(output_buffer + 12, &bigendian, 4);

    bigendian = htonl(pwcrypt_get_argon2_version_nr());
    memcpy(output_buffer + 16, &bigendian, 4);

    bigendian = htonl(argon2_cost_t);
    memcpy(output_buffer + 20, &bigendian, 4);

    bigendian = htonl(argon2_cost_m);
    memcpy(output_buffer + 24, &bigendian, 4);

    bigendian = htonl(argon2_parallelism);
    memcpy(output_buffer + 28, &bigendian, 4);

    // Generate random salt:
    dev_urandom(output_buffer + 32, 32);

    r = argon2id_hash_raw(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, output_buffer + 32, 32, key, sizeof(key));
    if (r != ARGON2_OK)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: argon2id failure! \"argon2id_hash_raw\" returned: %d\n", r);
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    if (pwcrypt_memcmp(key, EMPTY64, 32) == 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Symmetric encryption key derivation failure!\n");
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    uint8_t* o = output_buffer + 64;

    switch (algo)
    {
        case PWCRYPT_ALGO_ID_AES256_GCM: {
            r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_setkey\" returned: %d\n", r);
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                goto exit;
            }

            while (processed < input_length)
            {
                size_t n = PWCRYPT_FILE_BUFFER_SIZE;
                size_t remaining = input_length - processed;

                if (n > remaining)
                {
                    n = remaining;
                }

                if (ccrushed != NULL)
                {
                    ccrush_free(ccrushed);
                    ccrushed = NULL;
                }

                // Generate random IV and fill tag with temporary random data:
                dev_urandom(o, 32);
                o += 32;

                r = ccrush_compress(input + processed, n, PWCRYPT_CCRUSH_BUFFER_SIZE_KIB, (int)compress, &ccrushed, &ccrushed_size);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Compression of input data before encryption failed! \"ccrush_compress\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_COMPRESSION_FAILURE;
                    goto exit;
                }

                bigendian = htonl((uint32_t)ccrushed_size);
                memcpy(o, &bigendian, 4);
                o += 4;

                r = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, ccrushed_size, o - 32 - 4, 16, NULL, 0, ccrushed, o, 16, o - 16 - 4);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_crypt_and_tag\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                    goto exit;
                }

                o += ccrushed_size;
                processed += n;
            }

            break;
        }
        case PWCRYPT_ALGO_ID_CHACHA20_POLY1305: {
            r = mbedtls_chachapoly_setkey(&chachapoly_ctx, key);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_chachapoly_setkey\" returned: %d\n", r);
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                goto exit;
            }

            while (processed < input_length)
            {
                size_t n = PWCRYPT_FILE_BUFFER_SIZE;
                size_t remaining = input_length - processed;

                if (n > remaining)
                {
                    n = remaining;
                }

                if (ccrushed != NULL)
                {
                    ccrush_free(ccrushed);
                    ccrushed = NULL;
                }

                // Generate random IV and fill tag with temporary random data:
                dev_urandom(o, 32);
                o += 32;

                r = ccrush_compress(input + processed, n, PWCRYPT_CCRUSH_BUFFER_SIZE_KIB, (int)compress, &ccrushed, &ccrushed_size);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Compression of input data before encryption failed! \"ccrush_compress\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_COMPRESSION_FAILURE;
                    goto exit;
                }

                bigendian = htonl((uint32_t)ccrushed_size);
                memcpy(o, &bigendian, 4);
                o += 4;

                r = mbedtls_chachapoly_encrypt_and_tag(&chachapoly_ctx, ccrushed_size, o - 32 - 4, NULL, 0, ccrushed, o, o - 16 - 4);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_chachapoly_encrypt_and_tag\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                    goto exit;
                }

                o += ccrushed_size;
                processed += n;
            }

            break;
        }
        default: {
            pwcrypt_fprintf(stderr, "pwcrypt: Invalid algorithm ID. %d is not a valid pwcrypt algo id!\n", algo);
            r = PWCRYPT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

    size_t output_buffer_length = o - output_buffer;

    if (output_base64)
    {
        r = mbedtls_base64_encode(NULL, 0, &output_buffer_base64_length, output_buffer, output_buffer_length);
        if (r != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Base64-encoding failed! Assessing encoded output length with \"mbedtls_base64_encode\" returned: %d\n", r);
            r = PWCRYPT_ERROR_BASE64_FAILURE;
            goto exit;
        }

        output_buffer_base64_size = output_buffer_base64_length;
        output_buffer_base64 = calloc(output_buffer_base64_size + 1, sizeof(uint8_t));

        if (output_buffer_base64 == NULL)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
            r = PWCRYPT_ERROR_OOM;
            goto exit;
        }

        r = mbedtls_base64_encode(output_buffer_base64, output_buffer_base64_size, &output_buffer_base64_length, output_buffer, output_buffer_length);
        if (r != 0)
        {
            pwcrypt_free(output_buffer_base64);
            pwcrypt_fprintf(stderr, "pwcrypt: Base64-encoding failed! \"mbedtls_base64_encode\" returned: %d\n", r);
            r = PWCRYPT_ERROR_BASE64_FAILURE;
            goto exit;
        }

        *output = output_buffer_base64;

        if (output_length != NULL)
        {
            *output_length = output_buffer_base64_length;
        }
    }
    else
    {
        free_output_buffer = 0;

        *output = output_buffer;

        if (output_length != NULL)
        {
            *output_length = output_buffer_length;
        }
    }

exit:

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_chachapoly_free(&chachapoly_ctx);

    mbedtls_platform_zeroize(key, sizeof(key));

    if (ccrushed != NULL)
    {
        ccrush_free(ccrushed);
    }

    if (free_output_buffer && output_buffer != NULL)
    {
        mbedtls_platform_zeroize(output_buffer, output_buffer_size);
        pwcrypt_free(output_buffer);
    }

    return (r);
}

int pwcrypt_encrypt_file_raw(FILE* input_file, FILE* output_file, uint32_t compress, const uint8_t* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, uint32_t algo, uint32_t close_input_file, uint32_t close_output_file)
{
    if (input_file == NULL || password == NULL || output_file == NULL || input_file == output_file)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    int r = pwcrypt_assess_password_strength(password, password_length);
    if (r != 0)
    {
        return (r);
    }

#ifdef _WIN32
    if (input_file == stdin)
    {
        _setmode(_fileno(stdin), _O_BINARY);
    }
    if (output_file == stdout)
    {
        _setmode(_fileno(stdout), _O_BINARY);
    }
#endif

    uint8_t iv[16] = { 0x00 };
    uint8_t tag[16] = { 0x00 };
    uint8_t key[32] = { 0x00 };

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    mbedtls_chachapoly_context chachapoly_ctx;
    mbedtls_chachapoly_init(&chachapoly_ctx);

    size_t temp_counter = 0;
    uint8_t* temp_in_buffer = NULL;
    uint8_t* temp_out_buffer = NULL;

    uint8_t* ccrushed = NULL;
    size_t ccrushed_size = 0;

    temp_in_buffer = malloc(PWCRYPT_FILE_BUFFER_SIZE);
    temp_out_buffer = malloc(PWCRYPT_FILE_BUFFER_SIZE);

    if (temp_in_buffer == NULL || temp_out_buffer == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Out of memory... (failed to allocate internal temporary buffers)");
        r = PWCRYPT_ERROR_OOM;
        goto exit;
    }

    // [0 - 3]      (4B)   uint32_t:     Pwcrypt Version Number
    // [4 - 7]      (4B)   uint32_t:     Pwcrypt Algo ID
    // [8 - 11]     (4B)   uint32_t:     Pwcrypt Compression Enabled
    // [12 - 15]    (4B)   uint32_t:     Pwcrypt Base64 Encoded
    // [16 - 19]\   (4B)   uint32_t:     Argon2 Version Number
    // [20 - 23] |  (4B)   uint32_t:     Argon2 Cost T
    // [24 - 27] |  (4B)   uint32_t:     Argon2 Cost M
    // [28 - 31] |  (4B)   uint32_t:     Argon2 Parallelism
    // [32 - 63]/   (32B)  uint8_t[32]:  Argon2 Salt
    // [64 - 79]\   (16B)  uint8_t[16]:  AES-256 GCM IV (or 12B ChaCha20-Poly1305 IV, zero-padded)
    // [80 - 95] |  (16B)  uint8_t[16]:  AES-256 GCM Tag (or ChaCha20-Poly1305 Tag)
    // [96 - 99] |  (4B)   uint32_t:     Chunk length
    // [100 - n]/   (n B)  uint8_t[n]:   Chunk content (compressed + encrypted ciphertext)
    // [(n+1) - ...]                     (The last 4 sections make up a chunk; there can be as many chunks as needed)

    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);

    if (!argon2_cost_t)
        argon2_cost_t = PWCRYPT_ARGON2_T_COST;

    if (!argon2_cost_m)
        argon2_cost_m = PWCRYPT_ARGON2_M_COST;

    if (!argon2_parallelism)
        argon2_parallelism = PWCRYPT_ARGON2_PARALLELISM;

    uint32_t bigendian = htonl(pwcrypt_get_version_nr());
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write pwcrypt version number \"%d\" header to output file.\n", bigendian);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    bigendian = htonl(algo);
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write pwcrypt algo id to the output file.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    bigendian = htonl(compress);
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write pwcrypt compression parameter \"%d\" to the output file.\n", bigendian);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    bigendian = 0;
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write pwcrypt base64 parameter as header (value = 0) to output file.\n", bigendian);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    bigendian = htonl(pwcrypt_get_argon2_version_nr());
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write Argon2 version number \"%d\" header to output file.\n", bigendian);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    bigendian = htonl(argon2_cost_t);
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write Argon2 time cost parameter \"%d\" as header to output file.\n", bigendian);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    bigendian = htonl(argon2_cost_m);
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write Argon2 memory cost parameter \"%d\" as header to output file.\n", bigendian);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    bigendian = htonl(argon2_parallelism);
    if (fwrite(&bigendian, 4, 1, output_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write Argon2 parallelism parameter \"%d\" as header to output file.\n", bigendian);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    // Generate random salt:
    uint8_t salt[32];
    dev_urandom(salt, sizeof(salt));

    if (fwrite(salt, 1, sizeof(salt), output_file) != sizeof(salt))
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write salt to output file.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    r = argon2id_hash_raw(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, salt, 32, key, sizeof(key));
    if (r != ARGON2_OK)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: argon2id failure! \"argon2id_hash_raw\" returned: %d\n", r);
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    if (pwcrypt_memcmp(key, EMPTY64, 32) == 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Symmetric encryption key derivation failure!\n");
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    switch (algo)
    {
        case PWCRYPT_ALGO_ID_AES256_GCM: {
            r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_setkey\" returned: %d\n", r);
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                goto exit;
            }

            while ((temp_counter = fread(temp_in_buffer, 1, PWCRYPT_FILE_BUFFER_SIZE, input_file)) != 0)
            {
                // Generate random IV:
                dev_urandom(iv, sizeof(iv));

                if (ccrushed != NULL)
                {
                    ccrush_free(ccrushed);
                    ccrushed = NULL;
                }

                r = ccrush_compress(temp_in_buffer, temp_counter, PWCRYPT_CCRUSH_BUFFER_SIZE_KIB, (int)compress, &ccrushed, &ccrushed_size);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Compression of input file before encryption failed! \"ccrush_compress\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_COMPRESSION_FAILURE;
                    goto exit;
                }

                r = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, ccrushed_size, iv, 16, NULL, 0, ccrushed, temp_out_buffer, 16, tag);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_crypt_and_tag\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                    goto exit;
                }

                if (fwrite(iv, 1, 16, output_file) != 16)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write out IV value to output file. \"fwrite\" did not succeed in writing out the full 16 bytes...\n");
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }

                if (fwrite(tag, 1, 16, output_file) != 16)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write out GCM tag value to output file. \"fwrite\" did not succeed in writing out the full 16 bytes...\n");
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }

                bigendian = htonl((uint32_t)ccrushed_size); // This is safe as long as the PWCRYPT_FILE_BUFFER_SIZE value doesn't exceed uint32_t's max value.
                if (fwrite(&bigendian, 4, 1, output_file) != 1)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write chunk length \"%d\" to output file.\n", bigendian);
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }

                if (fwrite(temp_out_buffer, 1, ccrushed_size, output_file) != ccrushed_size)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write out chunk ciphertext to output file. \"fwrite\" did not succeed in writing out the bytes...\n");
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }
            }

            break;
        }
        case PWCRYPT_ALGO_ID_CHACHA20_POLY1305: {
            r = mbedtls_chachapoly_setkey(&chachapoly_ctx, key);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_chachapoly_setkey\" returned: %d\n", r);
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                goto exit;
            }

            while ((temp_counter = fread(temp_in_buffer, 1, PWCRYPT_FILE_BUFFER_SIZE, input_file)) != 0)
            {
                // Generate random IV:
                dev_urandom(iv, sizeof(iv));

                if (ccrushed != NULL)
                {
                    ccrush_free(ccrushed);
                    ccrushed = NULL;
                }

                r = ccrush_compress(temp_in_buffer, temp_counter, (PWCRYPT_FILE_BUFFER_SIZE / 1024), (int)compress, &ccrushed, &ccrushed_size);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Compression of input file before encryption failed! \"ccrush_compress\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_COMPRESSION_FAILURE;
                    goto exit;
                }

                r = mbedtls_chachapoly_encrypt_and_tag(&chachapoly_ctx, ccrushed_size, iv, NULL, 0, ccrushed, temp_out_buffer, tag);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_crypt_and_tag\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                    goto exit;
                }

                if (fwrite(iv, 1, 16, output_file) != 16)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write out IV value to output file. \"fwrite\" did not succeed in writing out the full 16 bytes...\n");
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }

                if (fwrite(tag, 1, 16, output_file) != 16)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write out ChaCha20-Poly1305 tag value to output file. \"fwrite\" did not succeed in writing out the full 16 bytes...\n");
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }

                bigendian = htonl((uint32_t)ccrushed_size); // This is safe as long as the PWCRYPT_FILE_BUFFER_SIZE value doesn't exceed uint32_t's max value.
                if (fwrite(&bigendian, 4, 1, output_file) != 1)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write chunk length \"%d\" to output file.\n", bigendian);
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }

                if (fwrite(temp_out_buffer, 1, ccrushed_size, output_file) != ccrushed_size)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! Failed to write out chunk ciphertext to output file. \"fwrite\" did not succeed in writing out the bytes...\n");
                    r = PWCRYPT_ERROR_FILE_FAILURE;
                    goto exit;
                }
            }

            break;
        }
        default: {
            pwcrypt_fprintf(stderr, "pwcrypt: Invalid algorithm ID. %d is not a valid pwcrypt algo id!\n", algo);
            r = PWCRYPT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

exit:

    if (close_input_file)
        fclose(input_file);

    if (close_output_file)
        fclose(output_file);

    if (ccrushed != NULL)
        ccrush_free(ccrushed);

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_chachapoly_free(&chachapoly_ctx);

    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(&input_file, sizeof(&input_file));
    mbedtls_platform_zeroize(&output_file, sizeof(&output_file));
    mbedtls_platform_zeroize(temp_in_buffer, sizeof(temp_in_buffer));
    mbedtls_platform_zeroize(temp_out_buffer, sizeof(temp_out_buffer));

    pwcrypt_free(temp_in_buffer);
    pwcrypt_free(temp_out_buffer);

    return (r);
}

int pwcrypt_encrypt_file(const char* input_file_path, size_t input_file_path_length, uint32_t compress, const uint8_t* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, uint32_t algo, const char* output_file_path, size_t output_file_path_length)
{
    if (input_file_path == NULL || input_file_path_length != strlen(input_file_path) || password == NULL || output_file_path == NULL || output_file_path_length != strlen(output_file_path))
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    int r = pwcrypt_assess_password_strength(password, password_length);
    if (r != 0)
    {
        return (r);
    }

    FILE* input_file = pwcrypt_fopen(input_file_path, "rb");
    FILE* output_file = pwcrypt_fopen(output_file_path, "wb");

    if (input_file == NULL || output_file == NULL)
    {
        if (input_file != NULL)
        {
            fclose(input_file);
        }
        if (output_file != NULL)
        {
            fclose(output_file);
        }
        pwcrypt_fprintf(stderr, "pwcrypt: \"pwcrypt_encrypt_file\" function failed to open input and/or output file.");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        return (r);
    }

    return pwcrypt_encrypt_file_raw(input_file, output_file, compress, password, password_length, argon2_cost_t, argon2_cost_m, argon2_parallelism, algo, 1, 1);
}

int pwcrypt_decrypt(const uint8_t* encrypted_data, size_t encrypted_data_length, const uint8_t* password, size_t password_length, uint8_t** output, size_t* output_length)
{
    if (encrypted_data == NULL || encrypted_data_length <= 96 || password == NULL || password_length < 6 || output == NULL)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);

    size_t input_length = 0;
    uint32_t input_base64_encoded = 0;
    memcpy(&input_base64_encoded, encrypted_data + 12, 4);

    mbedtls_base64_decode(NULL, 0, &input_length, encrypted_data, encrypted_data_length);

    if (input_length == 0)
    {
        if (input_base64_encoded)
        {
            return PWCRYPT_ERROR_INVALID_ARGS;
        }
        input_length = encrypted_data_length;
    }

    uint8_t* input = malloc(input_length);
    if (input == NULL)
    {
        return PWCRYPT_ERROR_OOM;
    }

    int r = mbedtls_base64_decode(input, input_length, &input_length, encrypted_data, encrypted_data_length);
    if (r != 0)
    {
        if (input_base64_encoded)
        {
            pwcrypt_free(input);
            pwcrypt_fprintf(stderr, "pwcrypt: Base64-decoding failed! \"mbedtls_base64_decode\" returned: %d\n", r);
            return PWCRYPT_ERROR_BASE64_FAILURE;
        }
        memcpy(input, encrypted_data, input_length);
    }

    uint8_t key[32] = { 0x00 };

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    mbedtls_chachapoly_context chachapoly_ctx;
    mbedtls_chachapoly_init(&chachapoly_ctx);

    uint8_t iv[16];
    uint8_t tag[16];
    uint8_t salt[32];
    uint32_t pwcrypt_version_number, pwcrypt_algo_id, pwcrypt_compressed, argon2_version_number, argon2_cost_t, argon2_cost_m, argon2_parallelism;

    // [0 - 3]      (4B)   uint32_t:     Pwcrypt Version Number
    // [4 - 7]      (4B)   uint32_t:     Pwcrypt Algo ID
    // [8 - 11]     (4B)   uint32_t:     Pwcrypt Compression Enabled
    // [12 - 15]    (4B)   uint32_t:     Pwcrypt Base64 Encoded
    // [16 - 19]    (4B)   uint32_t:     Argon2 Version Number
    // [20 - 23]    (4B)   uint32_t:     Argon2 Cost T
    // [24 - 27]    (4B)   uint32_t:     Argon2 Cost M
    // [28 - 31]    (4B)   uint32_t:     Argon2 Parallelism
    // [32 - 63]    (32B)  uint8_t[32]:  Argon2 Salt
    // [64 - 79]    (16B)  uint8_t[16]:  AES-256 GCM IV (or 12B ChaCha20-Poly1305 IV, zero-padded)
    // [80 - 95]    (16B)  uint8_t[16]:  AES-256 GCM Tag (or ChaCha20-Poly1305 Tag)
    // [96 - ...]   Ciphertext

    memcpy(&pwcrypt_version_number, input, 4);
    memcpy(&pwcrypt_algo_id, input + 4, 4);
    memcpy(&pwcrypt_compressed, input + 8, 4);
    memcpy(&argon2_version_number, input + 16, 4); // [12 - 15] (input_base64_encoded) is copied earlier (see above).
    memcpy(&argon2_cost_t, input + 20, 4);
    memcpy(&argon2_cost_m, input + 24, 4);
    memcpy(&argon2_parallelism, input + 28, 4);
    memcpy(salt, input + 32, 32);
    memcpy(iv, input + 64, 16);
    memcpy(tag, input + 80, 16);

    pwcrypt_version_number = ntohl(pwcrypt_version_number);
    pwcrypt_algo_id = ntohl(pwcrypt_algo_id);
    pwcrypt_compressed = ntohl(pwcrypt_compressed);
    argon2_version_number = ntohl(argon2_version_number);
    argon2_cost_t = ntohl(argon2_cost_t);
    argon2_cost_m = ntohl(argon2_cost_m);
    argon2_parallelism = ntohl(argon2_parallelism);

    const size_t decrypted_length = (input_length - 96);
    uint8_t* decrypted = malloc(decrypted_length);

    if (decrypted == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        r = PWCRYPT_ERROR_OOM;
        goto exit;
    }

    r = argon2_hash(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, salt, sizeof(salt), key, sizeof(key), NULL, 0, Argon2_id, argon2_version_number);
    if (r != ARGON2_OK)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: argon2id failure! \"argon2_hash\" returned: %d\n", r);
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    if (pwcrypt_memcmp(key, EMPTY64, 32) == 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Symmetric decryption key derivation failure!\n");
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    switch (pwcrypt_algo_id)
    {
        case PWCRYPT_ALGO_ID_AES256_GCM: {
            r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_setkey\" returned: %d\n", r);
                r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                goto exit;
            }

            r = mbedtls_gcm_auth_decrypt(&aes_ctx, decrypted_length, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), input + 96, decrypted);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_auth_decrypt\" returned: %d\n", r);
                r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                goto exit;
            }

            break;
        }
        case PWCRYPT_ALGO_ID_CHACHA20_POLY1305: {
            r = mbedtls_chachapoly_setkey(&chachapoly_ctx, key);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_chachapoly_setkey\" returned: %d\n", r);
                r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                goto exit;
            }

            r = mbedtls_chachapoly_auth_decrypt(&chachapoly_ctx, decrypted_length, iv, NULL, 0, tag, input + 96, decrypted);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_chachapoly_auth_decrypt\" returned: %d\n", r);
                r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                goto exit;
            }

            break;
        }
        default: {
            pwcrypt_fprintf(stderr, "pwcrypt: Invalid algorithm ID. \"%d\" is not a valid pwcrypt algo id!\n", pwcrypt_algo_id);
            r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
            goto exit;
        }
    }

    assert(r == 0);

    size_t dl = 0;
    r = ccrush_decompress(decrypted, decrypted_length, 256, output, output_length ? output_length : &dl);
    if (r != 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption succeeded but decompression failed! \"ccrush_decompress\" returned: %d\n", r);
        r = PWCRYPT_ERROR_DECOMPRESSION_FAILURE;
        goto exit;
    }

exit:

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_chachapoly_free(&chachapoly_ctx);

    mbedtls_platform_zeroize(&pwcrypt_version_number, sizeof(uint32_t));
    mbedtls_platform_zeroize(&pwcrypt_algo_id, sizeof(uint32_t));
    mbedtls_platform_zeroize(&pwcrypt_compressed, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_version_number, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_cost_t, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_cost_m, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_parallelism, sizeof(uint32_t));

    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(tag, sizeof(tag));
    mbedtls_platform_zeroize(salt, sizeof(salt));

    mbedtls_platform_zeroize(input, input_length);
    pwcrypt_free(input);

    if (decrypted != NULL)
    {
        mbedtls_platform_zeroize(decrypted, decrypted_length);
        pwcrypt_free(decrypted);
    }

    return (r);
}

int pwcrypt_decrypt_file_raw(FILE* input_file, FILE* output_file, const uint8_t* password, size_t password_length, uint32_t close_input_file, uint32_t close_output_file)
{
    if (input_file == NULL || output_file == NULL || input_file == output_file || password == NULL || password_length < 6)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);

#ifdef _WIN32
    if (input_file == stdin)
    {
        _setmode(_fileno(stdin), _O_BINARY);
    }
    if (output_file == stdout)
    {
        _setmode(_fileno(stdout), _O_BINARY);
    }
#endif

    int r = -1;

    uint8_t key[32] = { 0x00 };

    size_t temp_counter = 0;
    uint8_t* temp_in_buffer = NULL;
    uint8_t* temp_out_buffer = NULL;

    uint8_t* cuncrushed = NULL;
    size_t cuncrushed_size = 0;

    FILE* temp_file = NULL;
    char temp_file_path[256] = { 0x00 };

    pwcrypt_get_temp_filepath(temp_file_path);

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    mbedtls_chachapoly_context chachapoly_ctx;
    mbedtls_chachapoly_init(&chachapoly_ctx);

    uint32_t pwcrypt_version_number;
    uint32_t pwcrypt_algo_id;
    uint32_t pwcrypt_compressed;
    uint32_t argon2_version_number;
    uint32_t argon2_cost_t;
    uint32_t argon2_cost_m;
    uint32_t argon2_parallelism;
    uint8_t salt[32];
    uint8_t iv[16];
    uint8_t tag[16];

    // [0 - 3]      (4B)   uint32_t:     Pwcrypt Version Number
    // [4 - 7]      (4B)   uint32_t:     Pwcrypt Algo ID
    // [8 - 11]     (4B)   uint32_t:     Pwcrypt Compression Enabled
    // [12 - 15]    (4B)   uint32_t:     Pwcrypt Base64 Encoded
    // [16 - 19]\   (4B)   uint32_t:     Argon2 Version Number
    // [20 - 23] |  (4B)   uint32_t:     Argon2 Cost T
    // [24 - 27] |  (4B)   uint32_t:     Argon2 Cost M
    // [28 - 31] |  (4B)   uint32_t:     Argon2 Parallelism
    // [32 - 63]/   (32B)  uint8_t[32]:  Argon2 Salt
    // [64 - 79]\   (16B)  uint8_t[16]:  AES-256 GCM IV (or 12B ChaCha20-Poly1305 IV, zero-padded)
    // [80 - 95] |  (16B)  uint8_t[16]:  AES-256 GCM Tag (or ChaCha20-Poly1305 Tag)
    // [96 - 99] |  (4B)   uint32_t:     Chunk length
    // [100 - n]/   (n B)  uint8_t[n]:   Chunk content (compressed + encrypted ciphertext)
    // [(n+1) - ...]                     (The last 4 sections make up a chunk; there can be as many chunks as needed)

    temp_in_buffer = malloc(PWCRYPT_FILE_BUFFER_SIZE);
    temp_out_buffer = malloc(PWCRYPT_FILE_BUFFER_SIZE);

    if (temp_in_buffer == NULL || temp_out_buffer == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Out of memory... (failed to allocate internal temporary buffers)");
        r = PWCRYPT_ERROR_OOM;
        goto exit;
    }

    if (fread(&pwcrypt_version_number, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read pwcrypt version number from the input file header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    if (fread(&pwcrypt_algo_id, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read pwcrypt algo id from the input file's header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    if (fread(&pwcrypt_compressed, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read compression parameter from the input file header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    uint32_t unused = 0;
    if (fread(&unused, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure while reading the input file's pwcrypt header block while trying to seek forward 4 bytes.\n", r);
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    if (fread(&argon2_version_number, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read Argon2 version number from the input file header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    if (fread(&argon2_cost_t, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read Argon2 time cost parameter from the input file header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    if (fread(&argon2_cost_m, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read Argon2 memory cost parameter from the input file header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    if (fread(&argon2_parallelism, 4, 1, input_file) != 1)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read Argon2 parallelism parameter from the input file header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    if (fread(salt, 1, 32, input_file) != 32)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read salt bytes from the input file header block.\n");
        r = PWCRYPT_ERROR_FILE_FAILURE;
        goto exit;
    }

    pwcrypt_version_number = ntohl(pwcrypt_version_number);
    pwcrypt_algo_id = ntohl(pwcrypt_algo_id);
    pwcrypt_compressed = ntohl(pwcrypt_compressed);
    argon2_version_number = ntohl(argon2_version_number);
    argon2_cost_t = ntohl(argon2_cost_t);
    argon2_cost_m = ntohl(argon2_cost_m);
    argon2_parallelism = ntohl(argon2_parallelism);

    r = argon2_hash(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, salt, sizeof(salt), key, sizeof(key), NULL, 0, Argon2_id, argon2_version_number);
    if (r != ARGON2_OK)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: argon2id failure! \"argon2_hash\" returned: %d\n", r);
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    if (pwcrypt_memcmp(key, EMPTY64, 32) == 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Symmetric decryption key derivation failure!\n");
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    if (pwcrypt_version_number >= 440)
    {
        uint32_t chunk_length = 0;

    loop:

        if (fread(iv, 1, 16, input_file) != 16)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read IV bytes from the input file header block.\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        if (fread(tag, 1, 16, input_file) != 16)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read auth tag/MAC from the input file header block.\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        if (fread(&chunk_length, 4, 1, input_file) != 1)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read chunk length from the input file.\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        chunk_length = ntohl(chunk_length);

        if (chunk_length == 0)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Attempted to read empty chunk from the input file.\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        size_t remaining = chunk_length;

        for (;;)
        {
            temp_counter = fread(temp_in_buffer, 1, remaining < PWCRYPT_FILE_BUFFER_SIZE ? remaining : PWCRYPT_FILE_BUFFER_SIZE, input_file);

            if (temp_counter == 0)
                break;

            remaining -= temp_counter;

            if (remaining == 0)
                goto loop;
        }
    }
    else
    {
        if (fread(iv, 1, 16, input_file) != 16)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read IV bytes from the input file header block.\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        if (fread(tag, 1, 16, input_file) != 16)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to read auth tag/MAC from the input file header block.\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        temp_file = pwcrypt_fopen(temp_file_path, "wb");
        if (temp_file == NULL)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failed due to temporary file access (write access) failure!\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        switch (pwcrypt_algo_id)
        {
            case PWCRYPT_ALGO_ID_AES256_GCM: {
                r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_setkey\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                r = mbedtls_gcm_starts(&aes_ctx, MBEDTLS_GCM_DECRYPT, iv, sizeof(iv));
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_starts\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                while ((temp_counter = fread(temp_in_buffer, 1, PWCRYPT_FILE_BUFFER_SIZE, input_file)) != 0)
                {
                    r = mbedtls_gcm_update(&aes_ctx, temp_in_buffer, temp_counter, temp_out_buffer, temp_counter, &temp_counter);
                    if (r != 0)
                    {
                        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_update\" returned: %d\n", r);
                        r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                        goto exit;
                    }

                    if (fwrite(temp_out_buffer, 1, temp_counter, temp_file) != temp_counter)
                    {
                        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to write %xu bytes to disk.\n", temp_counter);
                        r = PWCRYPT_ERROR_FILE_FAILURE;
                        goto exit;
                    }
                }

                r = mbedtls_gcm_finish(&aes_ctx, temp_out_buffer + 16, 0, &temp_counter, temp_out_buffer, 16);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_finish\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                r = pwcrypt_memcmp(tag, temp_out_buffer, 16);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! The GCM auth tag value (checksum) verification failed... The ciphertext doesn't seem to be authentic and might have been tampered with!\n");
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                break;
            }
            case PWCRYPT_ALGO_ID_CHACHA20_POLY1305: {

                r = mbedtls_chachapoly_setkey(&chachapoly_ctx, key);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_chachapoly_setkey\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                r = mbedtls_chachapoly_starts(&chachapoly_ctx, iv, MBEDTLS_CHACHAPOLY_DECRYPT);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_chachapoly_starts\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                while ((temp_counter = fread(temp_in_buffer, 1, PWCRYPT_FILE_BUFFER_SIZE, input_file)) != 0)
                {
                    r = mbedtls_chachapoly_update(&chachapoly_ctx, temp_counter, temp_in_buffer, temp_out_buffer);
                    if (r != 0)
                    {
                        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_chachapoly_update\" returned: %d\n", r);
                        r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                        goto exit;
                    }

                    if (fwrite(temp_out_buffer, 1, temp_counter, temp_file) != temp_counter)
                    {
                        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Failed to write %xu bytes to disk.\n", temp_counter);
                        r = PWCRYPT_ERROR_FILE_FAILURE;
                        goto exit;
                    }
                }

                r = mbedtls_chachapoly_finish(&chachapoly_ctx, temp_out_buffer);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_chachapoly_finish\" returned: %d\n", r);
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                r = pwcrypt_memcmp(tag, temp_out_buffer, 16);
                if (r != 0)
                {
                    pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! The MAC value check failed... The ciphertext doesn't seem to be authentic and might have been tampered with!\n");
                    r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                    goto exit;
                }

                break;
            }
            default: {
                pwcrypt_fprintf(stderr, "pwcrypt: Invalid algorithm ID. \"%d\" is not a valid pwcrypt algo id!\n", pwcrypt_algo_id);
                r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
                goto exit;
            }
        }

        assert(r == 0);

        fclose(temp_file);

        temp_file = pwcrypt_fopen(temp_file_path, "rb");
        if (temp_file == NULL)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption failed due to temporary file access (read access) failure!\n");
            r = PWCRYPT_ERROR_FILE_FAILURE;
            goto exit;
        }

        r = ccrush_decompress_file_raw(temp_file, output_file, 4096, 0, 0);
        if (r != 0)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Decryption succeeded but decompression failed! \"ccrush_decompress_file\" returned: %d\n", r);
            r = PWCRYPT_ERROR_DECOMPRESSION_FAILURE;
            goto exit;
        }
    }

exit:

    if (temp_file != NULL)
        fclose(temp_file);

    if (close_input_file)
        fclose(input_file);

    if (close_output_file)
        fclose(output_file);

    remove(temp_file_path);
    mbedtls_platform_zeroize(temp_file_path, sizeof(temp_file_path));

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_chachapoly_free(&chachapoly_ctx);

    mbedtls_platform_zeroize(&pwcrypt_version_number, sizeof(uint32_t));
    mbedtls_platform_zeroize(&pwcrypt_algo_id, sizeof(uint32_t));
    mbedtls_platform_zeroize(&pwcrypt_compressed, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_version_number, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_cost_t, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_cost_m, sizeof(uint32_t));
    mbedtls_platform_zeroize(&argon2_parallelism, sizeof(uint32_t));

    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(tag, sizeof(tag));
    mbedtls_platform_zeroize(salt, sizeof(salt));

    pwcrypt_free(temp_in_buffer);
    pwcrypt_free(temp_out_buffer);

    return (r);
}

int pwcrypt_decrypt_file(const char* input_file_path, size_t input_file_path_length, const uint8_t* password, size_t password_length, const char* output_file_path, size_t output_file_path_length)
{
    if (input_file_path == NULL || strlen(input_file_path) != input_file_path_length || output_file_path == NULL || strlen(output_file_path) != output_file_path_length || password == NULL || password_length < 6)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);

    FILE* input_file = pwcrypt_fopen(input_file_path, "rb");
    FILE* output_file = pwcrypt_fopen(output_file_path, "wb");

    if (input_file == NULL || output_file == NULL)
    {
        if (input_file != NULL)
        {
            fclose(input_file);
        }
        if (output_file != NULL)
        {
            fclose(output_file);
        }
        pwcrypt_fprintf(stderr, "pwcrypt: \"pwcrypt_decrypt_file\" function failed to open input and/or output file.");
        return PWCRYPT_ERROR_FILE_FAILURE;
    }

    return pwcrypt_decrypt_file_raw(input_file, output_file, password, password_length, 1, 1);
}

FILE* pwcrypt_fopen(const char* filename, const char* mode)
{
#ifdef _WIN32
    wchar_t* wpath = malloc(PWCRYPT_MAX_WIN_FILEPATH_LENGTH * sizeof(wchar_t));
    if (wpath == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Out of memory...");
        return NULL;
    }

    wchar_t wmode[256];

    wpath[0] = 0x00;
    wmode[0] = 0x00;

    MultiByteToWideChar(CP_UTF8, 0, filename, -1, wpath, PWCRYPT_MAX_WIN_FILEPATH_LENGTH);
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 256);

    FILE* file = _wfopen(wpath, wmode);
    pwcrypt_free(wpath);
    return file;
#else // Hope that the fopen() implementation on whatever platform you're on accepts UTF-8 encoded strings. For most *nix environments, this holds true :)
    return fopen(filename, mode);
#endif
}

// https://github.com/GlitchedPolygons/l8w8jwt/pull/52
int pwcrypt_memcmp(const void* mem1, const void* mem2, size_t n)
{
    const unsigned char *c1, *c2;
    unsigned short d, r, m;

#if USE_VOLATILE_TEMPORARY
    volatile unsigned short v;
#else
    unsigned short v;
#endif

    c1 = mem1;
    c2 = mem2;

    r = 0;
    while (n)
    {
        /*
         * Take the low 8 bits of r (in the range 0x00 to 0xff,
         * or 0 to 255);
         * As explained elsewhere, the low 8 bits of r will be zero
         * if and only if all bytes compared so far were identical;
         * Zero-extend to a 16-bit type (in the range 0x0000 to
         * 0x00ff);
         * Add 255, yielding a result in the range 255 to 510;
         * Save that in a volatile variable to prevent
         * the compiler from trying any shortcuts (the
         * use of a volatile variable depends on "#ifdef
         * USE_VOLATILE_TEMPORARY", and most compilers won't
         * need it);
         * Divide by 256 yielding a result of 1 if the original
         * value of r was non-zero, or 0 if r was zero;
         * Subtract 1, yielding 0 if r was non-zero, or -1 if r
         * was zero;
         * Convert to unsigned short, yielding 0x0000 if r was
         * non-zero, or 0xffff if r was zero;
         * Save in m.
         */
        v = ((unsigned short)(unsigned char)r) + 255;
        m = v / 256 - 1;

        /*
         * Get the values from *c1 and *c2 as unsigned char (each will
         * be in the range 0 to 255, or 0x00 to 0xff);
         * Convert them to signed int values (still in the
         * range 0 to 255);
         * Subtract them using signed arithmetic, yielding a
         * result in the range -255 to +255;
         * Convert to unsigned short, yielding a result in the range
         * 0xff01 to 0xffff (for what was previously -255 to
         * -1), or 0, or in the range 0x0001 to 0x00ff (for what
         * was previously +1 to +255).
         */
        d = (unsigned short)((int)*c1 - (int)*c2);

        /*
         * If the low 8 bits of r were previously 0, then m
         * is now 0xffff, so (d & m) is the same as d, so we
         * effectively copy d to r;
         * Otherwise, if r was previously non-zero, then m is
         * now 0, so (d & m) is zero, so leave r unchanged.
         * Note that the low 8 bits of d will be zero if and
         * only if d == 0, which happens when *c1 == *c2.
         * The low 8 bits of r are thus zero if and only if the
         * entirety of r is zero, which happens if and only if
         * all bytes compared so far were equal.  As soon as a
         * non-zero value is stored in r, it remains unchanged
         * for the remainder of the loop.
         */
        r |= (d & m);

        /*
         * Increment pointers, decrement length, and loop.
         */
        ++c1;
        ++c2;
        --n;
    }

    /*
     * At this point, r is an unsigned value, which will be 0 if the
     * final result should be zero, or in the range 0x0001 to 0x00ff
     * (1 to 255) if the final result should be positive, or in the
     * range 0xff01 to 0xffff (65281 to 65535) if the final result
     * should be negative.
     *
     * We want to convert the unsigned values in the range 0xff01
     * to 0xffff to signed values in the range -255 to -1, while
     * converting the other unsigned values to equivalent signed
     * values (0, or +1 to +255).
     *
     * On a machine with two's complement arithmetic, simply copying
     * the underlying bits (with sign extension if int is wider than
     * 16 bits) would do the job, so something like this might work:
     *
     *     return (int16_t)r;
     *
     * However, that invokes implementation-defined behaviour,
     * because values larger than 32767 can't fit in a signed 16-bit
     * integer without overflow.
     *
     * To avoid any implementation-defined behaviour, we go through
     * these contortions:
     *
     * a. Calculate ((uint32_t)r + 0x8000).  The cast to uint32_t
     *    it to prevent problems on platforms where int is narrower
     *    than 32 bits.  If int is a larger than 32-bits, then the
     *    usual arithmetic conversions cause this addition to be
     *    done in unsigned int arithmetic.  If int is 32 bits
     *    or narrower, then this addition is done in uint32_t
     *    arithmetic.  In either case, no overflow or wraparound
     *    occurs, and the result from this step has a value that
     *    will be one of 0x00008000 (32768), or in the range
     *    0x00008001 to 0x000080ff (32769 to 33023), or in the range
     *    0x00017f01 to 0x00017fff (98049 to 98303).
     *
     * b. Cast the result from (a) to unsigned short.  This effectively
     *    discards the high bits of the result, in a way that is
     *    well defined by the C language.  The result from this step
     *    will be of type unsigned short, and its value will be one of
     *    0x8000 (32768), or in the range 0x8001 to 0x80ff (32769 to
     *    33023), or in the range 0x7f01 to 0x7fff (32513 to
     *    32767).
     *
     * c. Cast the result from (b) to int32_t.  We use int32_t
     *    instead of int because we need a type that's strictly
     *    larger than 16 bits, and the C standard allows
     *    implementations where int is only 16 bits.  The result
     *    from this step will be of type int32_t, and its value wll
     *    be one of 0x00008000 (32768), or in the range 0x00008001
     *    to 0x000080ff (32769 to 33023), or in the range 0x00007f01
     *    to 0x00007fff (32513 to 32767).
     *
     * d. Take the result from (c) and subtract 0x8000 (32768) using
     *    signed int32_t arithmetic.  The result from this step will
     *    be of type int32_t and the value will be one of
     *    0x00000000 (0), or in the range 0x00000001 to 0x000000ff
     *    (+1 to +255), or in the range 0xffffff01 to 0xffffffff
     *    (-255 to -1).
     *
     * e. Cast the result from (d) to int.  This does nothing
     *    interesting, except to make explicit what would have been
     *    implicit in the return statement.  The final result is an
     *    int in the range -255 to +255.
     *
     * Unfortunately, compilers don't seem to be good at figuring
     * out that most of this can be optimised away by careful choice
     * of register width and sign extension.
     *
     */
    return (/*e*/ int)(/*d*/
        (/*c*/ int)(/*b*/ unsigned short)(/*a*/ (unsigned int)r + 0x8000) - 0x8000);
}