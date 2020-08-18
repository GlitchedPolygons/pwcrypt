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

#include "pwcrypt.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <argon2.h>
#include <ccrush.h>
#include <assert.h>

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
        return r;
    }

    uint8_t* output_buffer = NULL;
    size_t output_buffer_length = 0;

    uint8_t* output_buffer_base64 = NULL;
    size_t output_buffer_base64_size = 0;
    size_t output_buffer_base64_length = 0;

    uint8_t key[32];
    memset(key, 0x00, sizeof(key));

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    mbedtls_chachapoly_context chachapoly_ctx;
    mbedtls_chachapoly_init(&chachapoly_ctx);

    uint8_t* input_buffer = NULL;
    size_t input_buffer_length = 0;

    r = ccrush_compress(input, input_length, 256, (int)compress, &input_buffer, &input_buffer_length);
    if (r != 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Compression of input data before encryption failed! \"ccrush_compress\" returned: %d\n", r);
        r = PWCRYPT_ERROR_COMPRESSION_FAILURE;
        goto exit;
    }

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

    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);

    output_buffer_length = (96 + input_buffer_length);

    output_buffer = calloc(output_buffer_length, sizeof(uint8_t));
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

    memcpy(output_buffer, &PWCRYPT_V, 4);
    memcpy(output_buffer + 4, &algo, 4);
    memcpy(output_buffer + 8, &compress, 4);
    memcpy(output_buffer + 12, &output_base64, 4);
    memcpy(output_buffer + 16, &ARGON2_V, 4);
    memcpy(output_buffer + 20, &argon2_cost_t, 4);
    memcpy(output_buffer + 24, &argon2_cost_m, 4);
    memcpy(output_buffer + 28, &argon2_parallelism, 4);

    // Generate random salt and iv:
    dev_urandom(output_buffer + 32, 32 + 16);

    r = argon2id_hash_raw(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, output_buffer + 32, 32, key, sizeof(key));
    if (r != ARGON2_OK)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: argon2id failure! \"argon2id_hash_raw\" returned: %d\n", r);
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        goto exit;
    }

    if (memcmp(key, EMPTY64, 32) == 0)
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

            r = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, input_buffer_length, output_buffer + 64, 16, NULL, 0, input_buffer, output_buffer + 96, 16, output_buffer + 80);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_crypt_and_tag\" returned: %d\n", r);
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                goto exit;
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

            r = mbedtls_chachapoly_encrypt_and_tag(&chachapoly_ctx, input_buffer_length, output_buffer + 64, NULL, 0, input_buffer, output_buffer + 96, output_buffer + 80);
            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_chachapoly_encrypt_and_tag\" returned: %d\n", r);
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                goto exit;
            }
            break;
        }
        default: {
            pwcrypt_fprintf(stderr, "pwcrypt: Invalid algorithm ID. %d is not a valid pwcrypt algo id!\n", algo);
            r = PWCRYPT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

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
        output_buffer_base64 = malloc(output_buffer_base64_size);
        if (output_buffer_base64 == NULL)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
            r = PWCRYPT_ERROR_OOM;
            goto exit;
        }

        r = mbedtls_base64_encode(output_buffer_base64, output_buffer_base64_length, &output_buffer_base64_length, output_buffer, output_buffer_length);
        if (r != 0)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: Base64-encoding failed! \"mbedtls_base64_encode\" returned: %d\n", r);
            r = PWCRYPT_ERROR_BASE64_FAILURE;
            goto exit;
        }

        *output = malloc(output_buffer_base64_length + 1);
        if (*output == NULL)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
            r = PWCRYPT_ERROR_OOM;
            goto exit;
        }

        memcpy(*output, output_buffer_base64, output_buffer_base64_length);
        (*output)[output_buffer_base64_length] = '\0';

        if (output_length != NULL)
        {
            *output_length = output_buffer_base64_length;
        }
    }
    else
    {
        *output = malloc(output_buffer_length + 1);
        if (*output == NULL)
        {
            pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
            r = PWCRYPT_ERROR_OOM;
            goto exit;
        }

        memcpy(*output, output_buffer, output_buffer_length);
        (*output)[output_buffer_length] = 0x00;

        if (output_length != NULL)
        {
            *output_length = output_buffer_length;
        }
    }

exit:

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_chachapoly_free(&chachapoly_ctx);

    mbedtls_platform_zeroize(key, sizeof(key));

    if (output_buffer != NULL)
    {
        mbedtls_platform_zeroize(output_buffer, output_buffer_length);
        free(output_buffer);
    }

    if (output_buffer_base64 != NULL)
    {
        mbedtls_platform_zeroize(output_buffer_base64, output_buffer_base64_size);
        free(output_buffer_base64);
    }

    if (input_buffer != NULL)
    {
        mbedtls_platform_zeroize(input_buffer, input_buffer_length);
        free(input_buffer);
    }

    return (r);
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
            free(input);
            pwcrypt_fprintf(stderr, "pwcrypt: Base64-decoding failed! \"mbedtls_base64_decode\" returned: %d\n", r);
            return PWCRYPT_ERROR_BASE64_FAILURE;
        }
        memcpy(input, encrypted_data, input_length);
    }

    uint8_t key[32];
    memset(key, 0x00, sizeof(key));

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

    if (memcmp(key, EMPTY64, 32) == 0)
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

    if (input != NULL)
    {
        mbedtls_platform_zeroize(input, input_length);
        free(input);
    }

    if (decrypted != NULL)
    {
        mbedtls_platform_zeroize(decrypted, decrypted_length);
        free(decrypted);
    }

    return (r);
}
