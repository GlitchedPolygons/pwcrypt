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
#include <stdlib.h>
#include <string.h>
#include <mbedtls/platform_util.h>

#include "pwcrypt.h"

#if _WIN32
#define PATH_MAX 260
#endif

static const char HELP_TEXT[] = "\n"
                                "pwcrypt \n"
                                "------- \n"
                                "%s  \n\n"
                                "Encrypt and decrypt strings using passwords. \n"
                                "The strings are compressed and then encrypted by deriving a symmetric encryption key from the password using Argon2. \n\n"
                                "Usage: \n\n"
                                "pwcrypt_cli \\\n\t{e|d} {input} {password} \\\n\t[--time-cost=INT] \\\n\t[--memory-cost=INT] \\\n\t[--parallelism=INT] \\\n\t[--compression=INT] \\\n\t[--algorithm=aes256-gcm|chachapoly] \\\n\t[--file=OUTPUT_FILE_PATH]\n\n"
                                "Examples: \n\n"
                                "-- Encrypting \n\n"
                                "  pwcrypt_cli e \"My string to encrypt.\" \"SUPER-safe Password123_!\" \n\n"
                                "-- Decrypting \n\n"
                                "  pwcrypt_cli d \"EwAAAAQAAAAAAAQAAgAAAFYjNGlNEnNMn5VtyW5hvxnKhdk9i\" \"SUPER-safe Password123_!\" \n";

int main(const int argc, const char* argv[])
{
    pwcrypt_enable_fprintf();

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        pwcrypt_fprintf(stdout, HELP_TEXT, PWCRYPT_VERSION_STR);
        return 0;
    }

    if (argc < 4)
    {
        pwcrypt_fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    const char* mode = argv[1];
    const size_t mode_length = strlen(mode);

    const char* text = argv[2];
    const size_t text_length = strlen(text);

    const char* password = argv[3];
    const size_t password_length = strlen(password);

    int r = -1;

    uint8_t file = 0;

    uint8_t* output = NULL;
    size_t output_length = 0;

    char output_file_path[PATH_MAX + 1];
    mbedtls_platform_zeroize(output_file_path, sizeof(output_file_path));

    uint32_t cost_m = 0;
    uint32_t cost_t = 0;
    uint32_t parallelism = 0;
    uint32_t compression = 8;
    uint32_t algo_id = PWCRYPT_ALGO_ID_AES256_GCM;

    if (mode_length != 1)
    {
        pwcrypt_fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
        r = PWCRYPT_ERROR_INVALID_ARGS;
        goto exit;
    }

    for (int i = 4; i < argc; ++i)
    {
        const char* arg = argv[i];

        if (strlen(arg) == 2 && strncmp(arg, "--", 2) == 0)
        {
            break;
        }

        if (strncmp("--time-cost=", arg, 12) == 0)
        {
            cost_t = strtol(arg + 12, NULL, 10);
            continue;
        }

        if (strncmp("--memory-cost=", arg, 14) == 0)
        {
            cost_m = strtol(arg + 14, NULL, 10);
            continue;
        }

        if (strncmp("--parallelism=", arg, 14) == 0)
        {
            parallelism = strtol(arg + 14, NULL, 10);
            continue;
        }

        if (strncmp("--compression=", arg, 14) == 0)
        {
            compression = strtol(arg + 14, NULL, 10);
            continue;
        }

        if (strncmp("--file=", arg, 7) == 0)
        {
            file = 1;

            const int n = snprintf(output_file_path, sizeof(output_file_path), "%s", arg + 7);
            if (n < 0 || n >= sizeof(output_file_path))
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Output file path too long: \"%s\" (maximum length is PATH_MAX=%d).\n", text, PATH_MAX);
                r = PWCRYPT_ERROR_FILE_FAILURE;
                goto exit;
            }

            continue;
        }

        if (strncmp("--algorithm=", arg, 12) == 0)
        {
            // Currently, this is OK since there are only 2 algos that have the IDs 0 and 1.
            // But at a later point, it would def. make sense to have a decent control block here for extracting algo ID from the CLI args.
            algo_id = (uint32_t)(strncmp("chachapoly", arg + 12, 10) == 0);
            continue;
        }
    }

    switch (*mode)
    {
        case 'e': {
            r = file //
                    ? pwcrypt_encrypt_file(text, text_length, compression, (uint8_t*)password, password_length, cost_t, cost_m, parallelism, algo_id, output_file_path, strlen(output_file_path)) //
                    : pwcrypt_encrypt((uint8_t*)text, text_length, compression, (uint8_t*)password, password_length, cost_t, cost_m, parallelism, algo_id, &output, &output_length, (uint32_t)(!file));

            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failed!\n");
            }
            break;
        }
        case 'd': {
            r = file //
                    ? pwcrypt_decrypt_file(text, text_length, (uint8_t*)password, password_length, output_file_path, strlen(output_file_path)) //
                    : pwcrypt_decrypt((uint8_t*)text, text_length, (uint8_t*)password, password_length, &output, &output_length);

            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Decryption failed!\n");
            }
            break;
        }
        default: {
            pwcrypt_fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
            r = PWCRYPT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

    if (r == 0 && output != NULL && !file)
    {
        pwcrypt_fprintf(stdout, "%s\n", output);
    }

exit:

    if (output != NULL)
    {
        mbedtls_platform_zeroize(output, output_length);
        free(output);
    }

    mbedtls_platform_zeroize(&file, sizeof(uint8_t));
    mbedtls_platform_zeroize(&text, sizeof(uint8_t*));
    mbedtls_platform_zeroize(&output, sizeof(uint8_t*));
    mbedtls_platform_zeroize(&compression, sizeof(uint32_t));
    mbedtls_platform_zeroize(&algo_id, sizeof(uint32_t));
    mbedtls_platform_zeroize(&cost_t, sizeof(uint32_t));
    mbedtls_platform_zeroize(&cost_m, sizeof(uint32_t));
    mbedtls_platform_zeroize(&parallelism, sizeof(uint32_t));
    mbedtls_platform_zeroize(output_file_path, sizeof(output_file_path));

    return (r);
}
