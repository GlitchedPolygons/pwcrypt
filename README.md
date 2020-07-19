# pwcrypt
## Easy peasy, password-based AES-256 GCM symmetric encryption squeezy

[![Codacy](https://app.codacy.com/project/badge/Grade/795a2f6752234b0590d7ec66470c7e2f)](https://www.codacy.com/manual/GlitchedPolygons/pwcrypt?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GlitchedPolygons/pwcrypt&amp;utm_campaign=Badge_Grade)
[![Codecov](https://codecov.io/gh/GlitchedPolygons/pwcrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/GlitchedPolygons/pwcrypt)
[![CircleCI](https://circleci.com/gh/GlitchedPolygons/pwcrypt/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/pwcrypt/tree/master)
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

#### Linking
If you use [CMake](https://cmake.org) you can just `add_subdirectory(path_to_submodule)` and then `target_link_libraries(your_project PRIVATE pwcrypt)` inside your CMakeLists.txt file.

### How to use the CLI
The pwcrypt command line interface works using the following (relatively rigid) sequence of arguments:

- Mode ('e' for encrypting, 'd' for decrypting)
- Input text (string to encrypt or decrypt)
- Password (string to encrypt the input with)
- [Optional params for encryption]

#### Encrypting

`pwcrypt e "My string to encrypt" "VERY-safe_password123!"`

You can pass optional (integer) arguments for controlling key-derivation with [Argon2](https://github.com/P-H-C/phc-winner-argon2):

`--time-cost=4`
- The higher, the safer, the slower...

`--memory-cost=65536`
- This value is in KiB and sets the used Argon2 memory cost.

`--parallelism=2`
- Sets the amount of parallel threads to be used by Argon2

Passing `0` to these optional args is equivalent to omitting them, thus using the default values 
as defined inside [pwcrypt.h](https://github.com/GlitchedPolygons/pwcrypt/blob/master/include/pwcrypt.h).

#### Decrypting

`pwcrypt_cli d "EwAAAAQAAAAAAAQAAgAAAFYjNGlNEnNMn5VtyW5hvxnKhdk9i" "Decryption Password 123 !!!"`
