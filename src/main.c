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
#include "pwcrypt.h"

static const char HELP_TEXT[] = "\n"
                                "pwcrypt \n"
                                "------- \n"
                                "%s  \n\n"
                                "Encrypt and decrypt strings using passwords. \n"
                                "The strings are compressed and then encrypted by deriving a symmetric encryption key from the password using Argon2. \n\n"
                                "Usage: \n\n"
                                "pwcrypt_cli {e|d} {input} {password} [--time-cost=INT] [--memory-cost=INT] [--parallelism=INT] [--algorithm=aes256-gcm|chachapoly] \n\n"
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

    if (mode_length != 1)
    {
        fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
        return PWCRYPT_ERROR_INVALID_ARGS;
    }

    int r = -1;
    char* output = NULL;

    switch (*mode)
    {
        case 'e': {
            uint8_t algo_id = PWCRYPT_ALGO_ID_AES256_GCM;
            uint32_t cost_t = 0, cost_m = 0, parallelism = 0;

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

                if (strncmp("--algorithm=", arg, 12) == 0)
                {
                    // Currently, this is OK since there are only 2 algos that have the IDs 0 and 1.
                    // But at a later point, it would def. make sense to have a decent control block here for extracting algo ID from the CLI args.
                    algo_id = (uint8_t)(strncmp("chachapoly", arg + 12, 10) == 0);
                    continue;
                }
            }

            r = pwcrypt_encrypt(text, text_length, password, password_length, cost_t, cost_m, parallelism, algo_id, &output);
            if (r != 0)
            {
                fprintf(stderr, "pwcrypt: Encryption failed!\n");
            }

            break;
        }
        case 'd': {
            r = pwcrypt_decrypt(text, text_length, password, password_length, &output);
            if (r != 0)
            {
                fprintf(stderr, "pwcrypt: Decryption failed!\n");
            }
            break;
        }
        default: {
            fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
            return PWCRYPT_ERROR_INVALID_ARGS;
        }
    }

    if (r == 0 && output)
    {
        fprintf(stdout, "%s\n", output);
        memset(output, 0x00, strlen(output));
        free(output);
    }

    return r;
}
