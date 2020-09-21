#!/bin/bash

#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

if [ "$(whoami)" = "root" ]; then
  echo "  Please don't run as root/using sudo..."
  exit
fi

PREVCC="$CC"
if command -v clang >/dev/null 2>&1
then
    echo "-- Clang found on system, great! Long live LLVM! :D"
    export CC=clang
fi

REPO=$(dirname "$0")
rm -rf "$REPO"/out
rm -rf "$REPO"/build
mkdir -p "$REPO"/build/shared && cd "$REPO"/build || exit
cp -r ../include ./
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DPWCRYPT_ONLY_BUILD_LIB=Off -DPWCRYPT_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release .. || exit
cmake --build . --config Release || exit
cd shared || exit
cmake -DBUILD_SHARED_LIBS=On -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DPWCRYPT_BUILD_DLL=On -DPWCRYPT_ONLY_BUILD_LIB=On -DPWCRYPT_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release ../.. || exit
cmake --build . --config Release || exit
cd .. || exit
mkdir static || exit
cd static || exit
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DPWCRYPT_BUILD_DLL=Off -DPWCRYPT_ONLY_BUILD_LIB=On -DPWCRYPT_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release ../.. || exit
cmake --build . --config Release || exit
cd .. || exit
VER=$(grep VERSION_STR include/*.h | sed -e "s/^#define PWCRYPT_VERSION_STR\ \"//" -e "s/\"$//" | tr -d '\n' | tr -d '\r\n')
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
CPU=$(uname -m)
FILENAME="pwcrypt-${VER}-${OS}-${CPU}.tar.gz"
tar -czvf "${FILENAME}" "pwcrypt_cli" "Release/pwcrypt_cli.exe" "include/pwcrypt.h" "shared/Release/pwcrypt.dll" "shared/Release/pwcrypt.exp" "shared/Release/pwcrypt.lib" "shared/*.dylib" "shared/*.dylib*" "shared/*.so" "shared/*.so*" "static/*.a" "static/Release/pwcrypt.lib"
cd "$REPO" || exit
export CC="$PREVCC"
echo "  Done. Exported build into $REPO/build"
echo "  Check out the .tar.gz file in there! "