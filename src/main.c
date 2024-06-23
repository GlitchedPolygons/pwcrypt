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

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#endif

static const char HELP_TEXT[] = "\n"
                                "pwcrypt \n"
                                "------- \n"
                                "%s  \n\n"
                                "Encrypt and decrypt strings using passwords. \n"
                                "The strings are compressed and then encrypted by deriving a symmetric encryption key from the password using Argon2. \n\n"
                                "Usage: \n\n"
                                "pwcrypt \\\n\t{e|d} {input} {password} \\\n\t[--time-cost=INT] \\\n\t[--memory-cost=INT] \\\n\t[--parallelism=INT] \\\n\t[--compression=INT] \\\n\t[--algorithm=aes256-gcm|chachapoly] \\\n\t[--file=OUTPUT_FILE_PATH]\n\n"
                                "Examples: \n\n"
                                "-- Encrypting \n\n"
                                "  pwcrypt e \"My string to encrypt.\" \"SUPER-safe Password123_!\" \n\n"
                                "-- Decrypting \n\n"
                                "  pwcrypt d \"EwAAAAQAAAAAAAQAAgAAAFYjNGlNEnNMn5VtyW5hvxnKhdk9i\" \"SUPER-safe Password123_!\" \n";

int main(const int argc, char* argv[])
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

    char* mode = argv[1];
    size_t mode_length = strlen(mode);

    char* text = argv[2];
    size_t text_length = strlen(text);

    char* password = argv[3];
    size_t password_length = strlen(password);

    int r = -1;

    uint8_t file = 0;
    const uint8_t use_stdin = (*text == '-' && text_length == 1);

    uint8_t* output = NULL;
    size_t output_length = 0;

    uint32_t cost_m = 0;
    uint32_t cost_t = 0;
    uint32_t parallelism = 0;
    uint32_t compression = 8;
    uint32_t algo_id = PWCRYPT_ALGO_ID_AES256_GCM;

    char* output_file_path = calloc(PWCRYPT_MAX_WIN_FILEPATH_LENGTH + 1, sizeof(char));
    if (output_file_path == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Out of memory...");
        return PWCRYPT_ERROR_OOM;
    }

#ifdef _WIN32
    int wargc;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);

    text_length = wcslen(wargv[2]);
    password_length = wcslen(wargv[3]);

    const size_t textbuffersize = (text_length * 4) + 1;
    const size_t passwordbuffersize = (password_length * 4) + 1;

    char* textbuffer = calloc(textbuffersize, sizeof(char));
    char* passwordbuffer = calloc(passwordbuffersize, sizeof(char));

    if (textbuffer == NULL || passwordbuffer == NULL)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Out of memory...");
        r = PWCRYPT_ERROR_OOM;
        goto exit;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, wargv[2], -1, textbuffer, (int)textbuffersize, NULL, NULL) == 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Failed to encode the second CLI argument to UTF-8.");
        r = PWCRYPT_ERROR_INVALID_ARGS;
        goto exit;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, wargv[3], -1, passwordbuffer, (int)passwordbuffersize, NULL, NULL) == 0)
    {
        pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Failed to encode the third CLI argument to UTF-8.");
        r = PWCRYPT_ERROR_INVALID_ARGS;
        goto exit;
    }

    text = textbuffer;
    password = passwordbuffer;

    text_length = strlen(text);
    password_length = strlen(password);
#endif

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

#ifdef _WIN32
            if (WideCharToMultiByte(CP_UTF8, 0, wargv[i] + 7, -1, output_file_path, (int)PWCRYPT_MAX_WIN_FILEPATH_LENGTH, NULL, NULL) == 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Critical failure! Failed to encode the CLI argument \"--file=\" (the output file path) to UTF-8.");
                r = PWCRYPT_ERROR_INVALID_ARGS;
                goto exit;
            }
#else
            const int n = snprintf(output_file_path, PWCRYPT_MAX_WIN_FILEPATH_LENGTH, "%s", arg + 7);
            if (n < 0 || n >= PWCRYPT_MAX_WIN_FILEPATH_LENGTH)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Output file path too long: \"%s\" (maximum length is %d).\n", text, PWCRYPT_MAX_WIN_FILEPATH_LENGTH);
                r = PWCRYPT_ERROR_FILE_FAILURE;
                goto exit;
            }
#endif

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

    FILE* output_file = file //
                            ? pwcrypt_fopen(output_file_path, "wb")
                            : stdout;

    switch (*mode)
    {
        case 'e': {
            if (use_stdin)
            {
                r = pwcrypt_encrypt_file_raw(stdin, output_file, compression, (uint8_t*)password, password_length, cost_t, cost_m, parallelism, algo_id, 0, file);
            }
            else
            {
                r = file                                                                                                                                                                              //
                        ? pwcrypt_encrypt_file(text, text_length, compression, (uint8_t*)password, password_length, cost_t, cost_m, parallelism, algo_id, output_file_path, strlen(output_file_path)) //
                        : pwcrypt_encrypt((uint8_t*)text, text_length, compression, (uint8_t*)password, password_length, cost_t, cost_m, parallelism, algo_id, &output, &output_length, 1);
            }

            if (r != 0)
            {
                pwcrypt_fprintf(stderr, "pwcrypt: Encryption failed!\n");
            }
            break;
        }
        case 'd': {
            if (use_stdin)
            {
                r = pwcrypt_decrypt_file_raw(stdin, output_file, (uint8_t*)password, password_length, 0, file);
            }
            else
            {
                r = file                                                                                                                           //
                        ? pwcrypt_decrypt_file(text, text_length, (uint8_t*)password, password_length, output_file_path, strlen(output_file_path)) //
                        : pwcrypt_decrypt((uint8_t*)text, text_length, (uint8_t*)password, password_length, &output, &output_length);
            }

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

    if (output_file != NULL && output_file != stdout)
    {
        fclose(output_file);
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
    mbedtls_platform_zeroize(output_file_path, PWCRYPT_MAX_WIN_FILEPATH_LENGTH + 1);
    free(output_file_path);

#ifdef _WIN32
    free(textbuffer);
    free(passwordbuffer);
    LocalFree(wargv);
#endif

    return (r);
}
