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

static const char HELP_TEXT[] = "\n"
                                "pwcrypt \n"
                                "------- \n"
                                "%s  \n\n"
                                "Encrypt and decrypt strings using passwords. \n"
                                "The strings are compressed and then encrypted by deriving a symmetric encryption key from the password using Argon2. \n\n"
                                "Usage: \n\n"
                                "pwcrypt_cli {e|d} {input} {password} [--time-cost=INT] [--memory-cost=INT] [--parallelism=INT] [--compression=INT] [--algorithm=aes256-gcm|chachapoly] [--file=OUTPUT_FILE_PATH]\n\n"
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
        fprintf(stdout, HELP_TEXT, PWCRYPT_VERSION_STR);
        return 0;
    }

    if (argc < 4)
    {
        fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
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

    uint8_t* input = (uint8_t*)text;
    size_t input_length = text_length;

    FILE* input_file = NULL;

    uint8_t* output = NULL;
    size_t output_length = 0;

    FILE* output_file = NULL;

    uint32_t compression = 8;
    uint32_t algo_id = PWCRYPT_ALGO_ID_AES256_GCM;
    uint32_t cost_t = 0, cost_m = 0, parallelism = 0;

    if (mode_length != 1)
    {
        fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
        r = PWCRYPT_ERROR_INVALID_ARGS;
        goto exit;
    }

    for (int i = 4; i < argc; i++)
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
            input_file = fopen(text, "rb");
            if (input_file == NULL)
            {
                fprintf(stderr, "pwcrypt: Failure to open file \"%s\"\n", text);
                r = PWCRYPT_ERROR_FILE_FAILURE;
                goto exit;
            }

            file = 1;
            fseek(input_file, 0, SEEK_END);
            input_length = ftell(input_file);
            rewind(input_file);

            input = malloc(input_length);
            if (input == NULL)
            {
                fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
                r = PWCRYPT_ERROR_OOM;
                goto exit;
            }

            if (input_length != fread(input, sizeof(uint8_t), input_length, input_file))
            {
                fprintf(stderr, "pwcrypt: Failure to read file \"%s\"\n", text);
                r = PWCRYPT_ERROR_FILE_FAILURE;
                goto exit;
            }

            output_file = fopen(arg + 7, "wb");
            if (output_file == NULL)
            {
                fprintf(stderr, "pwcrypt: Failure to create output file %s\n", arg + 7);
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
            r = pwcrypt_encrypt(input, input_length, compression, (uint8_t*)password, password_length, cost_t, cost_m, parallelism, algo_id, &output, &output_length, (uint32_t)(!file));
            if (r != 0)
            {
                fprintf(stderr, "pwcrypt: Encryption failed!\n");
            }
            break;
        }
        case 'd': {
            r = pwcrypt_decrypt(input, input_length, (uint8_t*)password, password_length, &output, &output_length);
            if (r != 0)
            {
                fprintf(stderr, "pwcrypt: Decryption failed!\n");
            }
            break;
        }
        default: {
            fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
            r = PWCRYPT_ERROR_INVALID_ARGS;
            goto exit;
        }
    }

    if (r == 0 && output != NULL)
    {
        if (file)
        {
            if (output_length != fwrite(output, sizeof(uint8_t), output_length, output_file))
            {
                fprintf(stderr, "pwcrypt: Encryption failed! Couldn't write all %zu bytes into the output file...\n", output_length);
                r = PWCRYPT_ERROR_FILE_FAILURE;
                goto exit;
            }
        }
        else
        {
            fprintf(stdout, "%s\n", output);
        }
    }

exit:
    if (input_file != NULL)
    {
        fclose(input_file);
        mbedtls_platform_zeroize(&input_file, sizeof(FILE*));
    }

    if (output_file != NULL)
    {
        fclose(output_file);
        mbedtls_platform_zeroize(&output_file, sizeof(FILE*));
    }

    if (file && input != NULL)
    {
        mbedtls_platform_zeroize(input, input_length);
        free(input);
    }

    if (output != NULL)
    {
        mbedtls_platform_zeroize(output, output_length);
        free(output);
    }

    mbedtls_platform_zeroize(&file, sizeof(uint8_t));
    mbedtls_platform_zeroize(&input, sizeof(uint8_t*));
    mbedtls_platform_zeroize(&output, sizeof(uint8_t*));
    mbedtls_platform_zeroize(&compression, sizeof(uint32_t));
    mbedtls_platform_zeroize(&algo_id, sizeof(uint32_t));
    mbedtls_platform_zeroize(&cost_t, sizeof(uint32_t));
    mbedtls_platform_zeroize(&cost_m, sizeof(uint32_t));
    mbedtls_platform_zeroize(&parallelism, sizeof(uint32_t));

    return (r);
}
