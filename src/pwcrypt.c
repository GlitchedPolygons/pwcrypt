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
#include <argon2.h>
#include <stdlib.h>
#include <miniz.h>
#include <assert.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>

static const uint32_t ARGON2_V = (uint32_t)ARGON2_VERSION_NUMBER;

int pwcrypt_assess_password_strength(const char* password, size_t password_length)
{
    if (password_length < 6)
    {
        fprintf(stderr, "pwcrypt: Password too weak! Please use at least 6 characters, composed of at least 1 lowercase char, 1 uppercase char, 1 number and 1 special character!\n");
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
        fprintf(stderr, "pwcrypt: Please include at least 1 uppercase character in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    if (!(strength & 1 << 1))
    {
        fprintf(stderr, "pwcrypt: Please include at least 1 lowercase character in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    if (!(strength & 1 << 2))
    {
        fprintf(stderr, "pwcrypt: Please include at least 1 number in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    if (!(strength & 1 << 3))
    {
        fprintf(stderr, "pwcrypt: Please include at least 1 special character in your password!\n");
        return PWCRYPT_ERROR_PW_TOO_WEAK;
    }

    return 0;
}

int pwcrypt_encrypt(const char* text, size_t text_length, const char* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, char** out)
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

    if (text_length < 1)
    {
        return PWCRYPT_ERROR_INVALID_ARGS;
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

    mz_stream stream;
    memset(&stream, 0x00, sizeof(stream));

    size_t compressed_length = mz_compressBound(text_length);
    size_t compressed_size = compressed_length * sizeof(uint8_t);

    uint8_t* compressed = malloc(compressed_size);
    if (compressed == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    if ((text_length | compressed_length) > 0xFFFFFFFFU)
    {
        r = MZ_PARAM_ERROR;
        fprintf(stderr, "pwcrypt: Compression of input data failed! \"mz_ulong\" is 64-bits...\n");
        goto exit;
    }

    r = mz_deflateInit(&stream, MZ_DEFAULT_LEVEL);
    if (r != MZ_OK)
    {
        fprintf(stderr, "pwcrypt: Compression of input data failed! \"mz_deflateInit\" returned: %d\n", r);
        goto exit;
    }

    stream.next_in = (uint8_t*)text;
    stream.avail_in = (mz_uint32)text_length;
    stream.next_out = compressed;
    stream.avail_out = (mz_uint32)compressed_length;

    r = mz_deflate(&stream, MZ_FINISH);
    if (r != MZ_STREAM_END)
    {
        r = (r == MZ_OK) ? MZ_BUF_ERROR : r;
        goto exit;
    }

    compressed_length = stream.total_out;

    // [0 - 3]      (4B) uint32_t: Argon2 Version Number
    // [4 - 7]      (4B) uint32_t: Argon2 Cost T
    // [8 - 11]     (4B) uint32_t: Argon2 Cost M
    // [12 - 15]    (4B) uint32_t: Argon2 Parallelism
    // [16 - 47]    (32B) uint8_t[32]: Argon2 Salt
    // [48 - 63]    (16B) uint8_t[16]: AES-256 GCM IV
    // [64 - 79]    (16B) uint8_t[16]: AES-256 GCM Tag
    // [80 - ...]   Ciphertext

    assert(sizeof(uint32_t) == 4);
    output_length = (80 + compressed_length);

    output = calloc(output_length, sizeof(uint8_t));
    if (output == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
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
        fprintf(stderr, "pwcrypt: argon2id failure! \"argon2id_hash_raw\" returned: %d\n", r);
        goto exit;
    }

    if (memcmp(key, EMPTY64, 32) == 0)
    {
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        fprintf(stderr, "pwcrypt: AES key derivation failure!\n");
        goto exit;
    }

    r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
        fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_setkey\" returned: %d\n", r);
        goto exit;
    }

    r = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, compressed_length, output + 48, 16, NULL, 0, compressed, output + 80, 16, output + 64);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
        fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_crypt_and_tag\" returned: %d\n", r);
        goto exit;
    }

    r = mbedtls_base64_encode(NULL, 0, &output_base64_length, output, output_length);
    if (r != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
        r = PWCRYPT_ERROR_BASE64_FAILURE;
        fprintf(stderr, "pwcrypt: Base64-encoding failed! Assessing encoded output length with \"mbedtls_base64_encode\" returned: %d\n", r);
        goto exit;
    }

    output_base64_size = output_base64_length * sizeof(uint8_t);
    output_base64 = malloc(output_base64_size);
    if (output_base64 == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    r = mbedtls_base64_encode(output_base64, output_base64_length, &output_base64_length, output, output_length);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_BASE64_FAILURE;
        fprintf(stderr, "pwcrypt: Base64-encoding failed! \"mbedtls_base64_encode\" returned: %d\n", r);
        goto exit;
    }

    *out = calloc(output_base64_length + 1, sizeof(char));
    if (*out == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        goto exit;
    }

    snprintf(*out, output_base64_length, "%s", output_base64);

exit:

    mz_deflateEnd(&stream);
    mbedtls_gcm_free(&aes_ctx);
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
        memset(compressed, 0x00, compressed_size);
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

    const size_t b64_decoded_size = b64_decoded_length * sizeof(uint8_t);

    uint8_t* b64_decoded = malloc(b64_decoded_size);
    if (b64_decoded == NULL)
    {
        return PWCRYPT_ERROR_OOM;
    }

    r = mbedtls_base64_decode(b64_decoded, b64_decoded_length, &b64_decoded_length, (uint8_t*)text, text_length);
    if (r != 0)
    {
        free(b64_decoded);
        fprintf(stderr, "pwcrypt: Base64-decoding failed! \"mbedtls_base64_decode\" returned: %d\n", r);
        return PWCRYPT_ERROR_BASE64_FAILURE;
    }

    uint8_t key[32];
    memset(key, 0x00, sizeof(key));

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    mz_stream stream;
    memset(&stream, 0x00, sizeof(stream));

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

    const size_t decrypted_length = (b64_decoded_length - 80) * sizeof(uint8_t);
    uint8_t* decrypted = malloc(decrypted_length);
    if (decrypted == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    r = argon2_hash(argon2_cost_t, argon2_cost_m, argon2_parallelism, password, password_length, salt, sizeof(salt), key, sizeof(key), NULL, 0, Argon2_id, argon2_version_number);
    if (r != ARGON2_OK)
    {
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        fprintf(stderr, "pwcrypt: argon2id failure! \"argon2_hash\" returned: %d\n", r);
        goto exit;
    }

    if (memcmp(key, EMPTY64, 32) == 0)
    {
        r = PWCRYPT_ERROR_ARGON2_FAILURE;
        fprintf(stderr, "pwcrypt: AES key derivation failure!\n");
        goto exit;
    }

    r = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_DECRYPTION_FAILURE;
        fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_setkey\" returned: %d\n", r);
        goto exit;
    }

    r = mbedtls_gcm_auth_decrypt(&aes_ctx, decrypted_length, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), b64_decoded + 80, decrypted);
    if (r != 0)
    {
        fprintf(stderr, "pwcrypt: Decryption failure! \"mbedtls_gcm_auth_decrypt\" returned: %d\n", r);
        goto exit;
    }

exit:

    mz_inflateEnd(&stream);
    mbedtls_gcm_free(&aes_ctx);
    memset(key, 0x00, sizeof(key));
    memset(iv, 0x00, sizeof(iv));
    memset(tag, 0x00, sizeof(tag));
    memset(salt, 0x00, sizeof(salt));
    argon2_version_number = argon2_cost_t = argon2_cost_m = argon2_parallelism = 0;

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

    return r;
}