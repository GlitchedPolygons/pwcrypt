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

/**
 *  @file pwcrypt.h
 *  @author Raphael Beck
 *  @brief Encrypt and decrypt strings symmetrically using Argon2id key derivation + either AES-256 (GCM) or ChaCha20-Poly1305.
 */

#ifndef PWCRYPT_H
#define PWCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(PWCRYPT_DLL)
#ifdef PWCRYPT_BUILD_DLL
#define PWCRYPT_API __declspec(dllexport)
#else
#define PWCRYPT_API __declspec(dllimport)
#endif
#else
#define PWCRYPT_API
#endif

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Error message for invalid CLI arguments.
 */
static const char PWCRYPT_INVALID_ARGS_ERROR_MSG[] = "pwcrypt: Invalid arguments! Please run \"pwcrypt --help\" to find out how to use this program.\n";

/**
 * An array of 64 bytes of value 0x00.
 */
static const uint8_t EMPTY64[64] = {
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

/**
 * Current version of the used pwcrypt library.
 */
#define PWCRYPT_VERSION 440

/**
 * Current version of the used pwcrypt library (nicely-formatted string).
 */
#define PWCRYPT_VERSION_STR "4.4.0"

#ifndef PWCRYPT_ARGON2_T_COST
/**
 * Default Argon2 time cost parameter to use for key derivation if nothing else was specified.
 */
#define PWCRYPT_ARGON2_T_COST 4
#endif

#ifndef PWCRYPT_ARGON2_M_COST
/**
 * Default Argon2 memory cost parameter to use for key derivation if nothing else was specified.
 */
#define PWCRYPT_ARGON2_M_COST (1024 * 256)
#endif

#ifndef PWCRYPT_ARGON2_PARALLELISM
/**
 * Default Argon2 degree of parallelism parameter if nothing else was specified.
 */
#define PWCRYPT_ARGON2_PARALLELISM 2
#endif

/**
 * Algo ID for the (default) AES256-GCM encryption algorithm.
 */
#define PWCRYPT_ALGO_ID_AES256_GCM 0

/**
 * Algo ID for the ChaCha20-Poly1305 encryption algorithm.
 */
#define PWCRYPT_ALGO_ID_CHACHA20_POLY1305 1

#ifndef PWCRYPT_FILE_BUFFER_SIZE
/**
 * The buffer size in bytes to use for reading/writing files.
 */
#define PWCRYPT_FILE_BUFFER_SIZE (1024 * 512)
#endif

#ifndef PWCRYPT_CCRUSH_BUFFER_SIZE_KIB
/**
 * The buffer size in KiB to use for compressing/decompressing via ccrush.
 */
#define PWCRYPT_CCRUSH_BUFFER_SIZE_KIB 256
#endif

/**
 * Error code for invalid arguments passed to a pwcrypt function.
 */
#define PWCRYPT_ERROR_INVALID_ARGS (-1)

/**
 * Error code "out of memory", uh oh...
 */
#define PWCRYPT_ERROR_OOM 1000

/**
 * Error code for passwords that are too weak.
 */
#define PWCRYPT_ERROR_PW_TOO_WEAK 2000

/**
 * Error code for Argon2 key derivation failures.
 */
#define PWCRYPT_ERROR_ARGON2_FAILURE 3000

/**
 * Encryption failures return this error code.
 */
#define PWCRYPT_ERROR_ENCRYPTION_FAILURE 4000

/**
 * Error code for decryption failures. <p>
 * Hint: If you're having this and you're using pwcrypt as a library, try to set a breakpoint and step through the code to see what exactly is failing
 */
#define PWCRYPT_ERROR_DECRYPTION_FAILURE 5000

/**
 * Base-64 encoding/decoding failure.
 */
#define PWCRYPT_ERROR_BASE64_FAILURE 6000

/**
 * This error code is returned when encryption failed due to a failure to compress the input data (ccrush lib failure).
 */
#define PWCRYPT_ERROR_COMPRESSION_FAILURE 7000

/**
 * Error code for when decompressing data fails (ccrush lib failure)..
 */
#define PWCRYPT_ERROR_DECOMPRESSION_FAILURE 8000

/**
 * Error code for failures while handling files.
 */
#define PWCRYPT_ERROR_FILE_FAILURE 9000

/**
 * Error code for failures concerning the output buffer (which uses the chillbuff lib to grow dynamically).
 */
#define PWCRYPT_ERROR_CHILLBUFF_FAILURE 10000

/**
 * Picks the smaller of two numbers.
 */
#define PWCRYPT_MIN(x, y) (((x) < (y)) ? (x) : (y))

/**
 * Picks the bigger of two numbers.
 */
#define PWCRYPT_MAX(x, y) (((x) > (y)) ? (x) : (y))

#ifndef PWCRYPT_MAX_WIN_FILEPATH_LENGTH
/**
 * Maximum file path length on NTFS.
 */
#define PWCRYPT_MAX_WIN_FILEPATH_LENGTH (1024 * 32)
#endif

/**
 * Checks whether pwcrypt fprintf is enabled (whether errors are fprintfed into stderr).
 * @return Whether errors are fprintfed into stderr or not.
 */
PWCRYPT_API unsigned char pwcrypt_is_fprintf_enabled();

/**
 * Like fprintf() except it doesn't do anything. Like printing into \c /dev/null :D lots of fun!
 * @param stream [IGNORED]
 * @param format [IGNORED]
 * @param ... [IGNORED]
 * @return <c>0</c>
 */
static inline int pwcrypt_printvoid(FILE* stream, const char* format, ...)
{
    return 0;
}

/** @private */
extern int (*pwcrypt_fprintf_fptr)(FILE* stream, const char* format, ...);

/**
 * Enables pwcrypts' use of fprintf().
 */
PWCRYPT_API void pwcrypt_enable_fprintf();

/**
 * Disables pwcrypts' use of fprintf().
 */
PWCRYPT_API void pwcrypt_disable_fprintf();

/** @private */
#define pwcrypt_fprintf pwcrypt_fprintf_fptr

/**
 * (Tries to) read from \c /dev/urandom (or Windows equivalent, yeah...) filling the given \p output_buffer with \p output_buffer_size random bytes.
 * @param output_buffer Where to write the random bytes into.
 * @param output_buffer_size How many random bytes to write into \p output_buffer
 */
PWCRYPT_API void dev_urandom(uint8_t* output_buffer, size_t output_buffer_size);

/**
 * Gets a completely random, temporary file name (usually located within \c /var/tmp).
 * @param output_buffer Where to write the temporary file path into (must be a writeable char buffer of at least 256B).
 */
PWCRYPT_API void pwcrypt_get_temp_filepath(char output_buffer[256]);

/**
 * Retrieve the size of a file.
 * @param filepath The file path.
 * @return The file size (in bytes) if retrieval succeeded; \c 0 if getting the file size failed for some reason.
 */
PWCRYPT_API size_t pwcrypt_get_filesize(const char* filepath);

/**
 * Checks whether a given password is strong enough or not.
 * @param password Password string to check (does not need to be NUL-terminated; only \p password_length characters will be checked!).
 * @param password_length Length of the \p password string.
 * @return <c>0</c> if the password is OK; a non-zero error code if the password is too weak.
 */
PWCRYPT_API int pwcrypt_assess_password_strength(const uint8_t* password, size_t password_length);

/**
 * Encrypts an input string of data symmetrically with a password. <p>
 * The password string is fed into a customizable amount of Argon2id iterations to derive a <strong>256-bit symmetric key</strong>, with which the input will be encrypted and written into the output buffer.
 * @param input The input data to encrypt.
 * @param input_length Length of the \p input data array argument.
 * @param compress Should the input data be compressed before being encrypted? Pass <c>0</c> for no compression, or a compression level from <c>1</c> to <c>9</c> to pass to the deflate algorithm (<c>6</c> is a healthy default value to use for this).
 * @param password The password string (ideally a UTF8-encoded byte array, but you can obviously also encrypt using a file) with which to encrypt the \p input argument (this will be used to derive a 256-bit symmetric encryption key (e.g. AES-256 key) using Argon2id).
 * @param password_length Length of the \p password string argument.
 * @param argon2_cost_t The Argon2 time cost parameter (number of iterations) to use for deriving the symmetric encryption key. Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_T_COST.
 * @param argon2_cost_m The Argon2 memory cost parameter (in KiB) to use for key derivation.  Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_M_COST.
 * @param argon2_parallelism Degree of parallelism to use when deriving the symmetric encryption key from the password with Argon2 (number of parallel threads).  Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_PARALLELISM.
 * @param algo Which encryption algo to use (see the top of the pwcrypt.h header file for more infos).
 * @param output Pointer to the output buffer where to write the encrypted ciphertext into. This will be allocated and NUL-terminated on success; if anything fails, this will be left untouched! So you only need to pwcrypt_free() it on successful encryption.
 * @param output_length [OPTIONAL] Where to write the output buffer length into. Pass <c>NULL</c> if you don't care.
 * @param output_base64 Should the encrypted output bytes be base64-encoded for easy textual transmission (e.g. email)? If you decide to base64-encode the encrypted data buffer, please be aware that a NUL-terminator is appended at the end to allow usage as a C-string but it will not be counted in \p output_length. Pass <c>0</c> for raw binary output, or anything else for a human-readable, base64-encoded output string.
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
PWCRYPT_API int pwcrypt_encrypt(const uint8_t* input, size_t input_length, uint32_t compress, const uint8_t* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, uint32_t algo, uint8_t** output, size_t* output_length, uint32_t output_base64);

/**
 * Encrypts a file symmetrically with a password. <p>
 * The password string is fed into a customizable amount of Argon2id iterations to derive a <strong>256-bit symmetric key</strong>, with which the input will be encrypted and written into the output buffer.
 * @param input_file_path Full path to the file that needs to be encrypted. Must be UTF-8 encoded. Must be NUL-terminated and its \c strlen() must be equal to the \p input_file_path_length parameter.
 * @param input_file_path_length Length of the \p input_file_path string.
 * @param compress Should the input data be compressed before being encrypted? Pass <c>0</c> for no compression, or a compression level from <c>1</c> to <c>9</c> to pass to the deflate algorithm (<c>6</c> is a healthy default value to use for this).
 * @param password The password string (ideally a UTF8-encoded byte array, but you can obviously also encrypt using a file) with which to encrypt the \p input argument (this will be used to derive a 256-bit symmetric encryption key (e.g. AES-256 key) using Argon2id).
 * @param password_length Length of the \p password string argument.
 * @param argon2_cost_t The Argon2 time cost parameter (number of iterations) to use for deriving the symmetric encryption key. Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_T_COST.
 * @param argon2_cost_m The Argon2 memory cost parameter (in KiB) to use for key derivation.  Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_M_COST.
 * @param argon2_parallelism Degree of parallelism to use when deriving the symmetric encryption key from the password with Argon2 (number of parallel threads).  Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_PARALLELISM.
 * @param algo Which encryption algo to use (see the top of the pwcrypt.h header file for more infos).
 * @param output_file_path This is the full output file path where to write the encrypted file into.
 * @param output_file_path_length Length of the \p output_file_path string.
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
PWCRYPT_API int pwcrypt_encrypt_file(const char* input_file_path, size_t input_file_path_length, uint32_t compress, const uint8_t* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, uint32_t algo, const char* output_file_path, size_t output_file_path_length);

/**
 * Encrypts a file symmetrically with a password. <p>
 * The password string is fed into a customizable amount of Argon2id iterations to derive a <strong>256-bit symmetric key</strong>, with which the input will be encrypted and written into the output buffer.
 * @param input_file File that needs to be encrypted. Must not be \c NULL
 * @param output_file File handle of the output file into which the encryption result should be written into. Must not be \c NULL
 * @param compress Should the input data be compressed before being encrypted? Pass <c>0</c> for no compression, or a compression level from <c>1</c> to <c>9</c> to pass to the deflate algorithm (<c>6</c> is a healthy default value to use for this).
 * @param password The password string (ideally a UTF8-encoded byte array, but you can obviously also encrypt using a file) with which to encrypt the \p input argument (this will be used to derive a 256-bit symmetric encryption key (e.g. AES-256 key) using Argon2id).
 * @param password_length Length of the \p password string argument.
 * @param argon2_cost_t The Argon2 time cost parameter (number of iterations) to use for deriving the symmetric encryption key. Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_T_COST.
 * @param argon2_cost_m The Argon2 memory cost parameter (in KiB) to use for key derivation.  Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_M_COST.
 * @param argon2_parallelism Degree of parallelism to use when deriving the symmetric encryption key from the password with Argon2 (number of parallel threads).  Pass <c>0</c> to use the default value of #PWCRYPT_ARGON2_PARALLELISM.
 * @param algo Which encryption algo to use (see the top of the pwcrypt.h header file for more infos).
 * @param close_input_file Should the input file handle be <c>fclose</c>'d after usage? Pass <c>0</c> for "false" and anything else for "true".
 * @param close_output_file Should the output file handle be <c>fclose</c>'d after usage? Pass <c>0</c> for "false" and anything else for "true".
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
PWCRYPT_API int pwcrypt_encrypt_file_raw(FILE* input_file, FILE* output_file, uint32_t compress, const uint8_t* password, size_t password_length, uint32_t argon2_cost_t, uint32_t argon2_cost_m, uint32_t argon2_parallelism, uint32_t algo, uint32_t close_input_file, uint32_t close_output_file);

/**
 * Decrypts a string or a byte array that was encrypted using pwcrypt_encrypt(). <p>
 * @param encrypted_data The ciphertext to decrypt.
 * @param encrypted_data_length Length of the \p encrypted_data argument (string length or byte array size).
 * @param password The decryption password.
 * @param password_length Length of the \p password argument.
 * @param output Pointer to the output buffer where to write the decrypted data into. This will be allocated and NUL-terminated automatically on success; if anything fails, this will be left untouched! So you only need to pwcrypt_free() this if decryption succeeds.
 * @param output_length [OPTIONAL] Where to write the output buffer length into. Pass <c>NULL</c> if you don't care.
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
PWCRYPT_API int pwcrypt_decrypt(const uint8_t* encrypted_data, size_t encrypted_data_length, const uint8_t* password, size_t password_length, uint8_t** output, size_t* output_length);

/**
 * Decrypts a file that was encrypted using pwcrypt_encrypt_file().
 * @param input_file_path Full path to the file that needs to be decrypted. Must be UTF-8 encoded. Must be NUL-terminated and its \c strlen() must be equal to the \p input_file_path_length parameter.
 * @param input_file_path_length Length of the \p input_file_path string.
 * @param password The decryption password.
 * @param password_length Length of the \p password argument.
 * @param output_file_path This is the full output file path where to write the decrypted file into.
 * @param output_file_path_length Length of the \p output_file_path string.
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
PWCRYPT_API int pwcrypt_decrypt_file(const char* input_file_path, size_t input_file_path_length, const uint8_t* password, size_t password_length, const char* output_file_path, size_t output_file_path_length);

/**
 * Decrypts a file that was encrypted using pwcrypt_encrypt_file() or pwcrypt_encrypt_file_raw().
 * @param input_file File to decrypt. Must not be \c NULL
 * @param output_file File handle of the output file into which to write the decrypted result. Must not be \c NULL
 * @param password The decryption password.
 * @param password_length Length of the \p password argument.
 * @param close_input_file Should the input file handle be <c>fclose</c>'d after usage? Pass <c>0</c> for "false" and anything else for "true".
 * @param close_output_file Should the output file handle be <c>fclose</c>'d after usage? Pass <c>0</c> for "false" and anything else for "true".
 * @return <c>0</c> on success; non-zero error codes if something fails.
 */
PWCRYPT_API int pwcrypt_decrypt_file_raw(FILE* input_file, FILE* output_file, const uint8_t* password, size_t password_length, uint32_t close_input_file, uint32_t close_output_file);

/**
 * Gets the current pwcrypt version number (numeric).
 * @return Pwcrypt version number (32-bit unsigned integer).
 */
PWCRYPT_API uint32_t pwcrypt_get_version_nr();

/**
 * Gets the current Argon2 version number used by pwcrypt (numeric).
 * @return Argon2 version number (32-bit unsigned integer).
 */
PWCRYPT_API uint32_t pwcrypt_get_argon2_version_nr();

/**
 * Gets the current pwcrypt version number as a nicely-formatted, human-readable string.
 * @return Pwcrypt version number (MAJOR.MINOR.PATCH)
 */
PWCRYPT_API char* pwcrypt_get_version_nr_string();

/**
 * Wrapper around <c>free()</c> (mainly useful for C# interop).
 * @param ptr The memory to free (typically the output of one of the two main pwcrypt functions).
 */
PWCRYPT_API void pwcrypt_free(void* ptr);

/**
 * Wrapper around \c fopen()
 * @param filename File path.
 * @param mode File open mode ("r", "w", "rb", etc...)
 * @return \c FILE* or \c null
 */
PWCRYPT_API FILE* pwcrypt_fopen(const char* filename, const char* mode);

/**
 * Compares two blocks of memory against equality in a cryptographically safe manner (time-safe impl./constant-time comparison).
 * @param mem1 Memory block 1 to compare.
 * @param mem2 Memory block 2 to compare.
 * @param n How many bytes to compare.
 * @return Returns <code>0</code> if the two memory blocks are equal for the passed amount of bytes.
 */
PWCRYPT_API int pwcrypt_memcmp(const void* mem1, const void* mem2, size_t n);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PWCRYPT_H
