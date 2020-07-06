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
#include "pwcrypt.h"

int main(int argc, const char* argv[])
{
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "\nTODO: HELP\n");
        return 0;
    }

    if (argc != 4)
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

    switch (*mode)
    {
        case 'e':
            r = pwcrypt_encrypt(text, text_length, password, password_length, 0, 0, 0);
            if (r != 0)
            {
                fprintf(stderr, "pwcrypt: Encryption failed!\n");
            }
            break;
        case 'd':
            r = pwcrypt_decrypt(text, text_length, password, password_length);
            if (r != 0)
            {
                fprintf(stderr, "pwcrypt: Decryption failed!\n");
            }
            break;
        default:
            fprintf(stderr, PWCRYPT_INVALID_ARGS_ERROR_MSG);
            return PWCRYPT_ERROR_INVALID_ARGS;
    }

    return r;
}
