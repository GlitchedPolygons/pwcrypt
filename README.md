# pwcrypt
## Easy peasy, password-based symmetric encryption squeezy
### Encrypt files and text messages with a password

[![CircleCI](https://circleci.com/gh/GlitchedPolygons/pwcrypt/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/pwcrypt/tree/master)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/addkmk08sytildbp/branch/master?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/pwcrypt/branch/master)
[![Codecov](https://codecov.io/gh/GlitchedPolygons/pwcrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/GlitchedPolygons/pwcrypt)
[![License Shield](https://img.shields.io/badge/license-Apache--2.0-orange)](https://github.com/GlitchedPolygons/pwcrypt/blob/master/LICENSE)
[![API Docs](https://img.shields.io/badge/api-docs-informational.svg)](https://glitchedpolygons.github.io/pwcrypt/files.html)

---

### How to clone

`git clone --recursive https://github.com/GlitchedPolygons/pwcrypt.git`

### How to use the library

Just add **pwcrypt** as a git submodule to your project (e.g. into some `lib/` or `deps/` folder inside your project's repo; `{repo_root}/lib/` is used here in the following example).

```
git submodule add https://github.com/GlitchedPolygons/pwcrypt.git lib/pwcrypt
git submodule update --init --recursive
```

If you don't want to use git submodules, you can also start vendoring a specific version of **pwcrypt** by copying its full repo content into the folder where you keep your project's external libraries/dependencies.

Check out the [API docs](https://glitchedpolygons.github.io/pwcrypt/files.html) or the [`pwcrypt.h`](https://github.com/GlitchedPolygons/pwcrypt/blob/master/include/pwcrypt.h) header file to find out how to call the encrypt/decrypt functions in C.

### Building from source

#### CLI program (statically linked) + pwcrypt DLL/Shared library build

```bash
bash build.sh
```
This works on Windows too: just use the [Git Bash for Windows](https://git-scm.com/download/win) CLI!

If the build succeeds, you should now have a new `.tar.gz` file inside the `build/` directory!

#### MinGW on Windows

```bash
bash build-mingw.sh
```
Wanna compile using [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/installer/mingw-w64-install.exe)? Run this using e.g. "Git Bash for Windows". Make sure that you have your MinGW installation directory inside your `PATH` - otherwise this script will fail when trying to call `mingw32-make.exe`.

Official release builds are made using `mingw-w64/x86_64-8.1.0-posix-seh-rt_v6-rev0/mingw64/bin/gcc.exe`.

#### Static library

This builds the pwcrypt as a static lib (without its MbedTLS dependencies though; those you'd need to manually gather and link yourself from `build/mbedtls/library`!)

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -Dpwcrypt_PACKAGE=On -Dpwcrypt_ONLY_BUILD_LIB=On ..
cmake --build . --config Release
```

### Linking

If you use [CMake](https://cmake.org) you don't need to build from source externally: 
you can just `add_subdirectory(path_to_git_submodule)` and then `target_link_libraries(your_project PRIVATE pwcrypt)` inside your CMakeLists.txt file.

### How to use the CLI

The pwcrypt command line interface works using the following (relatively rigid) sequence of arguments:

- Mode ('e' for encrypting, 'd' for decrypting)
- Input text (string to encrypt or decrypt)
- Password (string to encrypt the input with)
- [Optional params for encryption]

```
pwcrypt {e|d} {input} {password} \
     [--time-cost=INT] \
     [--memory-cost=INT] \
     [--parallelism=INT] \
     [--compression=INT] \
     [--algorithm=aes256-gcm|chachapoly] \
     [--file=OUTPUT_FILE_PATH]
```

#### Encrypting

`pwcrypt e "My string to encrypt" "VERY-safe_password123!"`

You can append the following **optional** (integer) arguments for controlling key-derivation with [Argon2](https://github.com/P-H-C/phc-winner-argon2) at the end:

`--time-cost=4`
- The higher, the safer, the slower...

`--memory-cost=65536`
- This value is in KiB and sets the Argon2 memory cost parameter.

`--parallelism=2`
- Sets the amount of parallel threads to be used by Argon2

> Passing `0` to these optional args is equivalent to omitting them, thus using the default values 
> as defined inside [pwcrypt.h](https://github.com/GlitchedPolygons/pwcrypt/blob/master/include/pwcrypt.h).

`--compression=8`
- This value between `0` and `9` determines the compression level to use when deflating the input data to encrypt: `0` does not compress at all, and `9` compresses the most (but can be slower). Default is `8`. 

---

Append `--algorithm=chachapoly` at the end to use the [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539) encryption algorithm instead of the default value `aes256-gcm`.

#### Decrypting

`pwcrypt d "EwAAAAQAAAAAAAQAAgAAAFYjNGlNEnNMn5VtyW5hvxnKhdk9i" "Decryption Password 123 !!!"`

---

### Files instead of strings

The pwcrypt CLI supports encrypting/decrypting files instead of strings too: <p>
Append the argument `--file="/usr/some/output/filepath.bin"` containing the **output** file path,
and the result will be written into a file instead of printing it out to the console.
In this case, the `{input}` text argument will be treated as the path of the file to encrypt/decrypt, NOT as the input string to encrypt.

* Example:

<pre>
pwcrypt e "/home/someuser/secret.png" \
     "Extremely Safe Encryption 1337 PW" \
     --file="/home/someuser/enrypted-secret.png.pwcrypt" \
     --compression=0 \
     --algorithm=chachapoly
</pre>

Please keep in mind: <br>
The output string path is **definitive**: there will be no asking whether it's ok to overwrite existing files or not. 
So make sure to only confirm commands that you know won't cause losses!

#### stdin / stdout / pipes

Since [v4.3.0](https://github.com/GlitchedPolygons/pwcrypt/releases/tag/4.3.0) it is now possible to make the pwcrypt CLI read the input from `stdin`.

To do so, just pass `-` as the input parameter after the `e` or `d` argument. The `--file=/output/file/path/here` still works (and if it's not set, the output will be written to `stdout`).

```bash
# Encrypt file:

cat myfile.txt | pwcrypt e - "SuperSafeEncryptionPassword123" > myfile.txt.pwcrypt

# Decrypt file:

cat myfile.txt.pwcrypt | pwcrypt d - "SuperSafeEncryptionPassword123" > myfile_decrypted.txt
```

For example, to compress and encrypt a whole directory you could pipe the result of `tar` into `pwcrypt`. Such a command would look like this:

`tar -czf - -C /my/directory/to/compress/and/encrypt . | pwcrypt e - "SuperSafeEncryptionPassword123" --file=result.tar.gz.pwcrypt --compression=0 --algorithm=chachapoly`

The same thing can also be done using the `>` redirection (if you don't wanna type out the `--file=` argument).

`tar -czf - -C /my/directory/to/compress/and/encrypt . | pwcrypt e - "SuperSafeEncryptionPassword123" --algorithm=chachapoly --compression=0 > result.tar.gz.pwcrypt`

To decrypt the above example encrypted archive one would use the following command:

`cat result.tar.gz.pwcrypt | pwcrypt d - "SuperSafeEncryptionPassword123" | tar -xzf -`

### GUIs

You want the nice graphical stuff huh? The fully visualized presentation. With colors 'n' design n' stuff. We get it!

There is a (commercial) [Android app](https://play.google.com/store/apps/details?id=com.glitchedpolygons.pwcrypt) on the Google Play store called "psíthyros" that uses and wraps this library. It presents a very usable and accessible way of interacting with pwcrypt (for text messages, mainly).

<a href="https://play.google.com/store/apps/details?id=com.glitchedpolygons.pwcrypt"><img src="https://api.files.glitchedpolygons.com/api/v1/files/lr51n950no5bq2vm" width="150"></a>

The desktop client is available for the x64 CPU architecture on Windows, Linux and Mac. Check it out here on [the glitchedpolygons.com store](https://glitchedpolygons.com/projects/software/psithyros)!

---

[![Qt GUI Screenshot](https://api.files.glitchedpolygons.com/api/v1/files/gx9piwkhenm5n9c8)](https://glitchedpolygons.com/projects/software/psithyros)
