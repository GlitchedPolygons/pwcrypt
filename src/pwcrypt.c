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
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <argon2.h>
#include <ccrush.h>
#include <assert.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <mbedtls/chachapoly.h>

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

int pwcrypt_assess_password_strength(const char* password, const size_t password_length)
{
    if (password_length < 6)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Password too weak! Please use at least 6 characters, composed of at least 1 lowercase char, 1 uppercase char, 1 number and 1 special character!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    uint8_t strength = 0;

    for (int i = 0; i < password_length; ++i)
    {
        const char c = password[i];
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

int pwcrypt_encrypt(const char* text, size_t text_length, const char* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, uint8_t algo, char** out)
{
    if (text == NULL || text_length == 0 || password == NULL || out == NULL)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    int r = pwcrypt_assess_password_strength(password, password_length);
    if (r != 0)
    {
        return r;
    }

    uint8_t* output = NULL;
    size_t output_length = 0;

    uint8_t* output_base64 = NULL;
    size_t output_base64_size = 0;
    size_t output_base64_length = 0;

    uint8_t key[32];
    memset(key, 0x00, sizeof(key));

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    mbedtls_chachapoly_context chachapoly_ctx;
    mbedtls_chachapoly_init(&chachapoly_ctx);

    uint8_t* compressed = NULL;
    size_t compressed_length = 0;

    r = ccrush_compress((uint8_t*)text, text_length, 256, 8, &compressed, &compressed_length);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_COMPRESSION_FAILURE;
        pwcrypt_fprintf(stderr, "pwcrypt: Compression of text before encryption failed!\n");
        goto exit;
    }

    // [0 - 3]      (4B) uint32_t: Argon2 Version Number
    // [4 - 7]      (4B) uint32_t: Argon2 Cost T
    // [8 - 11]     (4B) uint32_t: Argon2 Cost M
    // [12 - 15]    (4B) uint32_t: Argon2 Parallelism
    // [16 - 47]    (32B) uint8_t[32]: Argon2 Salt
    // [48 - 63]    (16B) uint8_t[16]: AES-256 GCM IV
    // [64 - 79]    (16B) uint8_t[16]: AES-256 GCM Tag
    // [80 - ...]   Ciphertext (plaintext is first compressed, then encrypted)

    assert(sizeof(uint32_t) == 4);
    output_length = (80 + compressed_length);

    output = calloc(output_length, sizeof(uint8_t));
    if (output == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    if (!argon2_cost_t)
        argon2_cost_t = PWCRYPT_ARGON2_T_COST;

    if (!argon2_cost_m)
        argon2_cost_m = PWCRYPT_ARGON2_M_COST;

    if (!argon2_parallelism)
        argon2_parallelism = PWCRYPT_ARGON2_PARALLELISM;

    memcpy(output, &ARGON2_V, 4);
    memcpy(output + 4, &argon2_cost_t, 4);
    memcpy(output + 8, &argon2_cost_m, 4);
    memcpy(output + 12, &argon2_parallelism, 4);

    // Generate random salt and iv:
    dev_urandom(output + 16, 32 + 16);

    r = argon2id_hash_raw(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, output + 16, 32, key, sizeof(key));
    if (r != ARGON2_OK)
    {
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        pwcrypt_fprintf(stderr, "pwcrypt: argon2id failure! \"argon2id_hash_raw\" returned: %d\n", r);
        goto exit;
    }

    if (memcmp(key, EMPTY64, 32) == 0)
    {
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        pwcrypt_fprintf(stderr, "pwcrypt: Symmetric encryption key derivation failure!\n");
        goto exit;
    }

    switch (algo)
    {
        case PWCRYPT_ALGO_ID_AES256_GCM: {
            r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
            if (r != 0)
            {
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_setkey\" returned: %d\n", r);
                goto exit;
            }

            r = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, compressed_length, output + 48, 16, NULL, 0, compressed, output + 80, 16, output + 64);
            if (r != 0)
            {
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_crypt_and_tag\" returned: %d\n", r);
                goto exit;
            }
            break;
        }
        case PWCRYPT_ALGO_ID_CHACHA20_POLY1305: {
            r = mbedtls_chachapoly_setkey(&chachapoly_ctx, key);
            if (r != 0)
            {
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_chachapoly_setkey\" returned: %d\n", r);
                goto exit;
            }

            r = mbedtls_chachapoly_encrypt_and_tag(&chachapoly_ctx, compressed_length, output + 48, NULL, 0, compressed, output + 80, output + 64);
            if (r != 0)
            {
                r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_chachapoly_encrypt_and_tag\" returned: %d\n", r);
                goto exit;
            }
            break;
        }
        default: {
            r = PWCRYPT_ERROR_INVALID_ARGS;
            pwcrypt_fprintf(stderr, "pwcrypt: Invalid algorithm ID. %d is not a valid pwcrypt algo id!\n", (unsigned short)algo);
            goto exit;
        }
    }

    r = mbedtls_base64_encode(NULL, 0, &output_base64_length, output, output_length);
    if (r != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
        r = PWCRYPT_ERROR_BASE64_FAILURE;
        pwcrypt_fprintf(stderr, "pwcrypt: Base64-encoding failed! Assessing encoded output length with \"mbedtls_base64_encode\" returned: %d\n", r);
        goto exit;
    }

    output_base64_size = output_base64_length;
    output_base64 = malloc(output_base64_size);
    if (output_base64 == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    r = mbedtls_base64_encode(output_base64, output_base64_length, &output_base64_length, output, output_length);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_BASE64_FAILURE;
        pwcrypt_fprintf(stderr, "pwcrypt: Base64-encoding failed! \"mbedtls_base64_encode\" returned: %d\n", r);
        goto exit;
    }

    *out = calloc(++output_base64_length, sizeof(char));
    if (*out == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    snprintf(*out, output_base64_length, "%s", output_base64);

exit:

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_chachapoly_free(&chachapoly_ctx);

    memset(key, 0x00, sizeof(key));

    if (output != NULL)
    {
        memset(output, 0x00, output_length);
        free(output);
    }

    if (output_base64 != NULL)
    {
        memset(output_base64, 0x00, output_base64_size);
        free(output_base64);
    }

    if (compressed != NULL)
    {
        memset(compressed, 0x00, compressed_length);
        free(compressed);
    }

    return r;
}

int pwcrypt_decrypt(const char* text, size_t text_length, const char* password, size_t password_length, char** out)
{
    if (text == NULL || text_length < 107 || password == NULL || password_length < 6 || out == NULL)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    int r = -1;
    size_t b64_decoded_length = 0;
    mbedtls_base64_decode(NULL, 0, &b64_decoded_length, (uint8_t*)text, text_length);

    if (!b64_decoded_length)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    assert(sizeof(uint8_t) == 1);
    const size_t b64_decoded_size = b64_decoded_length;

    uint8_t* b64_decoded = malloc(b64_decoded_size);
    if (b64_decoded == NULL)
    {
        return PWCRYPT_ERROR_OOM;
    }

    r = mbedtls_base64_decode(b64_decoded, b64_decoded_length, &b64_decoded_length, (uint8_t*)text, text_length);
    if (r != 0)
    {
        free(b64_decoded);
        pwcrypt_fprintf(stderr, "pwcrypt: Base64-decoding failed! \"mbedtls_base64_decode\" returned: %d\n", r);
        return PWCRYPT_ERROR_BASE64_FAILURE;
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
    uint32_t argon2_version_number, argon2_cost_t, argon2_cost_m, argon2_parallelism;

    memcpy(&argon2_version_number, b64_decoded, 4);
    memcpy(&argon2_cost_t, b64_decoded + 4, 4);
    memcpy(&argon2_cost_m, b64_decoded + 8, 4);
    memcpy(&argon2_parallelism, b64_decoded + 12, 4);
    memcpy(salt, b64_decoded + 16, 32);
    memcpy(iv, b64_decoded + 48, 16);
    memcpy(tag, b64_decoded + 64, 16);

    const size_t decrypted_length = (b64_decoded_length - 80);
    uint8_t* decrypted = malloc(decrypted_length);

    uint8_t* decompressed = NULL;
    size_t decompressed_length = 0;

    if (decrypted == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    r = argon2_hash(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, salt, sizeof(salt), key, sizeof(key), NULL, 0, Argon2_id, argon2_version_number);
    if (r != ARGON2_OK)
    {
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        pwcrypt_fprintf(stderr, "pwcrypt: argon2id failure! \"argon2_hash\" returned: %d\n", r);
        goto exit;
    }

    if (memcmp(key, EMPTY64, 32) == 0)
    {
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        pwcrypt_fprintf(stderr, "pwcrypt: Symmetric decryption key derivation failure!\n");
        goto exit;
    }

    // Start trying out decryption algorithms, and jump to the next algo on failure:

    r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
        goto chachapoly;
    }

    r = mbedtls_gcm_auth_decrypt(&aes_ctx, decrypted_length, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), b64_decoded + 80, decrypted);
    if (r != 0)
    {
        goto chachapoly;
    }

    goto decrypted;

chachapoly:

    r = mbedtls_chachapoly_setkey(&chachapoly_ctx, key);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
        goto decrypted;
    }

    r = mbedtls_chachapoly_auth_decrypt(&chachapoly_ctx, decrypted_length, iv, NULL, 0, tag, b64_decoded + 80, decrypted);
    if (r != 0)
    {
        goto decrypted;
    }

    goto decrypted;

decrypted:

    if (r != 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption failure! Status code: %d\n", r);
        goto exit;
    }

    r = ccrush_decompress(decrypted, decrypted_length, 256, &decompressed, &decompressed_length);
    if (r != 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Decryption succeeded but decompression failed! \"ccrush_decompress\" returned: %d\n", r);
        goto exit;
    }

    *out = calloc(++decompressed_length, sizeof(char));
    if (*out == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        pwcrypt_fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    snprintf(*out, decompressed_length, "%s", decompressed);

exit:

    mbedtls_gcm_free(&aes_ctx);
    mbedtls_chachapoly_free(&chachapoly_ctx);
    argon2_version_number = argon2_cost_t = argon2_cost_m = argon2_parallelism = 0;

    memset(key, 0x00, sizeof(key));
    memset(iv, 0x00, sizeof(iv));
    memset(tag, 0x00, sizeof(tag));
    memset(salt, 0x00, sizeof(salt));

    if (b64_decoded != NULL)
    {
        memset(b64_decoded, 0x00, b64_decoded_size);
        free(b64_decoded);
    }

    if (decrypted != NULL)
    {
        memset(decrypted, 0x00, decrypted_length);
        free(decrypted);
    }

    if (decompressed != NULL)
    {
        memset(decompressed, 0x00, decompressed_length);
        free(decompressed);
    }

    return r;
}
