SET i=%CD%
SET repo=%~dp0
SET out="%repo%\build-msvc"
if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out%
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DPWCRYPT_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release ..
msbuild pwcrypt_cli.vcxproj /p:configuration=release
mkdir include\pwcrypt
xcopy ..\include\pwcrypt .\include\pwcrypt
tar -czvf pwcrypt.tar.gz include\pwcrypt\* Release\pwcrypt.lib Release\pwcrypt_cli.exe
cd %i%