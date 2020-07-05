#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <argon2.h>
#include <stdlib.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#endif

static const char PWCRYPT_INVALID_ARGS_ERROR_MSG[] = "pwcrypt: Invalid arguments! Please run \"pwcrypt-- help\" to find out how to use this program.\n";

static const unsigned char EMPTY64[64] = {
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

#define PWCRYPT_ARGON2_T_COST 4
#define PWCRYPT_ARGON2_M_COST (1 << 17)
#define PWCRYPT_ARGON2_PARALLELISM 2

#define PWCRYPT_ERROR_INVALID_ARGS -1
#define PWCRYPT_ERROR_OOM 1000
#define PWCRYPT_ERROR_PW_TOO_WEAK 2000
#define PWCRYPT_ERROR_ARGON2_FAILURE 3000
#define PWCRYPT_ERROR_ENCRYPTION_FAILURE 4000
#define PWCRYPT_ERROR_DECRYPTION_FAILURE 5000
#define PWCRYPT_ERROR_BASE64_FAILURE 6000

/**
 * (Tries to) read from <c>/dev/urandom</c> (or Windows equivalent, yeah...) filling the given \p output_buffer with \p output_buffer_size random bytes.
 * @param output_buffer Where to write the random bytes into.
 * @param output_buffer_size How many random bytes to write into \p output_buffer
 */
static inline void dev_urandom(unsigned char* output_buffer, const size_t output_buffer_size)
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

static int encrypt(const char* text, const size_t text_length, const char* password, const size_t password_length)
{
    int r = -1;

    if (password_length < 6)
    {
        fprintf(stderr, "pwcrypt: Password too weak! Please use at least 6 characters, composed of at least 1 lowercase char, 1 lowercase char, 1 number and 1 special character!\n");
        return PWCRYPT_ERROR_INVALID_ARGS;
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

    uint8_t key[32];
    memset(key, 0x00, sizeof(key));

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init(&aes_ctx);

    // [0 - 31]     32B Salt
    // [32 - 47]    16B IV
    // [48 - 63]    16B Tag
    // [64 - ...]   Ciphertext

    uint8_t* output = calloc(64 + text_length, sizeof(uint8_t));
    if (output == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    // Generate random salt and iv:
    dev_urandom(output, 32 + 16);

    r = argon2id_hash_raw(PWCRYPT_ARGON2_T_COST, PWCRYPT_ARGON2_M_COST, PWCRYPT_ARGON2_PARALLELISM, password, password_length, output, 32, key, sizeof(key));
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

    r = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, text_length, output + 32, 16, NULL, 0, (unsigned char*)text, output + 64, 16, output + 48);
    if (r != 0)
    {
        r = PWCRYPT_ERROR_ENCRYPTION_FAILURE;
        fprintf(stderr, "pwcrypt: Encryption failure! \"mbedtls_gcm_crypt_and_tag\" returned: %d\n", r);
        goto exit;
    }

    size_t base64_length;
    mbedtls_base64_encode(NULL, 0, &base64_length, output, 64 + text_length);

    uint8_t* base64 = malloc(base64_length);
    if (base64 == NULL)
    {
        r = PWCRYPT_ERROR_OOM;
        fprintf(stderr, "pwcrypt: OUT OF MEMORY!\n");
        goto exit;
    }

    r = mbedtls_base64_encode(base64, base64_length, &base64_length, output, 64 + text_length);
    if (r != 0)
    {
        free(base64);
        fprintf(stderr, "pwcrypt: Base64 encoding failed! \"mbedtls_base64_encode\" returned: %d\n", r);
        r = PWCRYPT_ERROR_BASE64_FAILURE;
        goto exit;
    }

    fprintf(stdout, "%s", base64);

exit:
    if (output != NULL)
    {
        free(output);
    }

    memset(key, 0x00, sizeof(key));
    mbedtls_gcm_free(&aes_ctx);

    return r;
}

static int decrypt(const char* text, const size_t text_length, const char* password, const size_t password_length)
{
    // TODO: impl
}

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
            r = encrypt(text, text_length, password, password_length);
            if (r != 0)
            {
                fprintf(stderr, "pwcrypt: Encryption failed!\n");
            }
            break;
        case 'd':
            r = decrypt(text, text_length, password, password_length);
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
