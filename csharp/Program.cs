using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;

namespace GlitchedPolygons.PwcryptSharp
{
    /// <summary>
    /// Pwcrypt C# wrapper class. <para> </para>
    /// Copy this class into your own C# project and then
    /// don't forget to copy the libs folder to your own project's build output directory!
    /// </summary>
    public class PwcryptSharpContext : IDisposable
    {
        #region Shared library loaders (per platform implementations)

        private interface ISharedLibLoadUtils
        {
            IntPtr LoadLibrary(string fileName);
            void FreeLibrary(IntPtr handle);
            IntPtr GetProcAddress(IntPtr handle, string name);
        }

        private class SharedLibLoadUtilsWindows : ISharedLibLoadUtils
        {
            [DllImport("kernel32.dll")]
            private static extern IntPtr LoadLibrary(string fileName);

            [DllImport("kernel32.dll")]
            private static extern int FreeLibrary(IntPtr handle);

            [DllImport("kernel32.dll")]
            private static extern IntPtr GetProcAddress(IntPtr handle, string procedureName);

            void ISharedLibLoadUtils.FreeLibrary(IntPtr handle)
            {
                FreeLibrary(handle);
            }

            IntPtr ISharedLibLoadUtils.GetProcAddress(IntPtr dllHandle, string name)
            {
                return GetProcAddress(dllHandle, name);
            }

            IntPtr ISharedLibLoadUtils.LoadLibrary(string fileName)
            {
                return LoadLibrary(fileName);
            }
        }

        private class SharedLibLoadUtilsLinux : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.so")]
            private static extern IntPtr dlopen(String fileName, int flags);

            [DllImport("libdl.so")]
            private static extern IntPtr dlsym(IntPtr handle, String symbol);

            [DllImport("libdl.so")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.so")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        private class SharedLibLoadUtilsMac : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlopen(String fileName, int flags);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlsym(IntPtr handle, String symbol);

            [DllImport("libdl.dylib")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        #endregion

        #region Function mapping

        private delegate void FreeDelegate(IntPtr mem);

        private delegate void EnableFprintfDelegate();

        private delegate void DisableFprintfDelegate();

        private delegate byte IsFprintfEnabledDelegate();

        private delegate IntPtr GetVersionNumberStringDelegate();

        private delegate uint GetVersionNumberDelegate();

        private delegate uint GetArgon2VersionNumberDelegate();

        private delegate void DevUrandomDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] outputArray,
            [MarshalAs(UnmanagedType.U8)] ulong outputArraySize
        );

        private delegate ulong GetFilesizeDelegate(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string filepath
        );

        private delegate int AssessPasswordStrengthDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] password,
            [MarshalAs(UnmanagedType.U8)] ulong passwordLength
        );

        private delegate int EncryptDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] inputData,
            [MarshalAs(UnmanagedType.U8)] ulong inputDataLength,
            [MarshalAs(UnmanagedType.U4)] uint compress,
            [MarshalAs(UnmanagedType.LPArray)] byte[] password,
            [MarshalAs(UnmanagedType.U8)] ulong passwordLength,
            [MarshalAs(UnmanagedType.U4)] uint argon2CostT,
            [MarshalAs(UnmanagedType.U4)] uint argon2CostM,
            [MarshalAs(UnmanagedType.U4)] uint argon2Parallelism,
            [MarshalAs(UnmanagedType.U4)] uint algo,
            out IntPtr output,
            out ulong outputLength,
            [MarshalAs(UnmanagedType.U4)] uint outputBase64
        );

        private delegate int DecryptDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] encryptedData,
            [MarshalAs(UnmanagedType.U8)] ulong encryptedDataLength,
            [MarshalAs(UnmanagedType.LPArray)] byte[] password,
            [MarshalAs(UnmanagedType.U8)] ulong passwordLength,
            out IntPtr output,
            out ulong outputLength
        );

        #endregion

        private readonly EnableFprintfDelegate enableFprintfDelegate;
        private readonly DisableFprintfDelegate disableFprintfDelegate;
        private readonly IsFprintfEnabledDelegate isFprintfEnabledDelegate;
        private readonly DevUrandomDelegate devUrandomDelegate;
        private readonly GetFilesizeDelegate getFilesizeDelegate;
        private readonly AssessPasswordStrengthDelegate assessPasswordStrengthDelegate;
        private readonly EncryptDelegate encryptDelegate;
        private readonly DecryptDelegate decryptDelegate;
        private readonly FreeDelegate freeDelegate;
        private readonly GetVersionNumberDelegate getVersionNumberDelegate;
        private readonly GetArgon2VersionNumberDelegate getArgon2VersionNumberDelegate;
        private readonly GetVersionNumberStringDelegate getVersionNumberStringDelegate;

        private readonly IntPtr lib;
        private readonly ISharedLibLoadUtils loadUtils;

        /// <summary>
        /// Absolute path to the shared library that is currently loaded into memory for this wrapper class.
        /// </summary>
        public string LoadedLibraryPath { get; }

        /// <summary>
        /// Creates a new pwcrypt instance. <para> </para>
        /// Make sure to create one only once and cache it as needed, since loading the DLLs into memory can negatively affect the performance.
        /// <param name="sharedLibPathOverride">[OPTIONAL] Don't look for a <c>lib/</c> folder and directly use this path as a pre-resolved, platform-specific shared lib/DLL file path. Pass this if you want to handle the various platform's paths yourself.</param>
        /// </summary>
        public PwcryptSharpContext(string sharedLibPathOverride = null)
        {
            string os;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
                loadUtils = new SharedLibLoadUtilsWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                os = "linux";
                loadUtils = new SharedLibLoadUtilsLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "mac";
                loadUtils = new SharedLibLoadUtilsMac();
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported OS");
            }

            if (!string.IsNullOrEmpty(sharedLibPathOverride))
            {
                LoadedLibraryPath = sharedLibPathOverride;
            }
            else
            {
                string cpu = RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X64 => "x64",
                    Architecture.X86 => "x86",
                    Architecture.Arm => "armeabi-v7a",
                    Architecture.Arm64 => "arm64-v8a",
                    _ => throw new PlatformNotSupportedException("CPU Architecture not supported!")
                };

                string path = Path.Combine(Path.GetFullPath(Path.GetDirectoryName(Assembly.GetCallingAssembly().Location) ?? "."), "lib", cpu, os);

                if (!Directory.Exists(path))
                {
                    throw new PlatformNotSupportedException($"Shared library not found in {path} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory. ");
                }

                bool found = false;
                foreach (string file in Directory.GetFiles(path))
                {
                    if (file.ToLower().Contains("pwcrypt"))
                    {
                        LoadedLibraryPath = Path.GetFullPath(Path.Combine(path, file));
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    throw new FileLoadException($"Shared library not found in {path} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory. ");
                }
            }

            lib = loadUtils.LoadLibrary(LoadedLibraryPath);
            if (lib == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr enableFprintf = loadUtils.GetProcAddress(lib, "pwcrypt_enable_fprintf");
            if (enableFprintf == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr disableFprintf = loadUtils.GetProcAddress(lib, "pwcrypt_disable_fprintf");
            if (disableFprintf == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr isFprintfEnabled = loadUtils.GetProcAddress(lib, "pwcrypt_is_fprintf_enabled");
            if (isFprintfEnabled == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getVersionNumber = loadUtils.GetProcAddress(lib, "pwcrypt_get_version_nr");
            if (getVersionNumber == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getVersionNumberString = loadUtils.GetProcAddress(lib, "pwcrypt_get_version_nr_string");
            if (getVersionNumberString == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getArgon2VersionNumber = loadUtils.GetProcAddress(lib, "pwcrypt_get_argon2_version_nr");
            if (getArgon2VersionNumber == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr devUrandom = loadUtils.GetProcAddress(lib, "dev_urandom");
            if (devUrandom == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getFilesize = loadUtils.GetProcAddress(lib, "pwcrypt_get_filesize");
            if (getFilesize == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr assessPasswordStrength = loadUtils.GetProcAddress(lib, "pwcrypt_assess_password_strength");
            if (assessPasswordStrength == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr encrypt = loadUtils.GetProcAddress(lib, "pwcrypt_encrypt");
            if (encrypt == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr decrypt = loadUtils.GetProcAddress(lib, "pwcrypt_decrypt");
            if (decrypt == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr free = loadUtils.GetProcAddress(lib, "pwcrypt_free");
            if (free == IntPtr.Zero)
            {
                goto hell;
            }

            enableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<EnableFprintfDelegate>(enableFprintf);
            disableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<DisableFprintfDelegate>(disableFprintf);
            isFprintfEnabledDelegate = Marshal.GetDelegateForFunctionPointer<IsFprintfEnabledDelegate>(isFprintfEnabled);
            getVersionNumberDelegate = Marshal.GetDelegateForFunctionPointer<GetVersionNumberDelegate>(getVersionNumber);
            getVersionNumberStringDelegate = Marshal.GetDelegateForFunctionPointer<GetVersionNumberStringDelegate>(getVersionNumberString);
            getArgon2VersionNumberDelegate = Marshal.GetDelegateForFunctionPointer<GetArgon2VersionNumberDelegate>(getArgon2VersionNumber);
            devUrandomDelegate = Marshal.GetDelegateForFunctionPointer<DevUrandomDelegate>(devUrandom);
            getFilesizeDelegate = Marshal.GetDelegateForFunctionPointer<GetFilesizeDelegate>(getFilesize);
            assessPasswordStrengthDelegate = Marshal.GetDelegateForFunctionPointer<AssessPasswordStrengthDelegate>(assessPasswordStrength);
            encryptDelegate = Marshal.GetDelegateForFunctionPointer<EncryptDelegate>(encrypt);
            decryptDelegate = Marshal.GetDelegateForFunctionPointer<DecryptDelegate>(decrypt);
            freeDelegate = Marshal.GetDelegateForFunctionPointer<FreeDelegate>(free);

            return;

            hell:
            throw new Exception($"Failed to load one or more functions from the shared library \"{LoadedLibraryPath}\"!");
        }

        private static byte[] MarshalReadBytes(IntPtr array, ulong arrayLength, int bufferSize = 1024 * 256)
        {
            using var ms = new MemoryStream((int)arrayLength);

            IntPtr i = array;
            ulong rem = arrayLength;
            byte[] buf = new byte[bufferSize];

            while (rem != 0)
            {
                int n = (int)Math.Min(rem, (ulong)buf.LongLength);
                Marshal.Copy(i, buf, 0, n);
                i = IntPtr.Add(i, n);
                rem -= (ulong)n;
                ms.Write(buf, 0, n);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Enables pwcrypt's use of fprintf(). 
        /// </summary>
        public void EnableConsoleLogging()
        {
            enableFprintfDelegate();
        }

        /// <summary>
        /// Disables pwcrypt's use of fprintf().
        /// </summary>
        public void DisableConsoleLogging()
        {
            disableFprintfDelegate();
        }

        /// <summary>
        /// Check whether this library is allowed to fprintf() into stdout or not.
        /// </summary>
        public bool IsConsoleLoggingEnabled()
        {
            byte r = isFprintfEnabledDelegate();
            return r != 0;
        }

        /// <summary>
        /// Retrieve the size of a file.
        /// </summary>
        /// <param name="filePath">The file path.</param>
        /// <returns>The file size (in bytes) if retrieval succeeded; <c>0</c> if getting the file size failed for some reason.</returns>
        ///
        public ulong GetFilesize(string filePath)
        {
            return getFilesizeDelegate(filePath);
        }

        /// <summary>
        /// Gets <paramref name="n"/> random bytes (on linux and mac via <c>/dev/urandom</c>, on Windows using <c>BCryptGenRandom</c>).
        /// </summary>
        /// <param name="n">How many random bytes to return?</param>
        /// <returns>An array of <paramref name="n"/> random bytes.</returns>
        public byte[] GetRandomBytes(ulong n)
        {
            byte[] o = new byte[n];
            devUrandomDelegate(o, n);
            return o;
        }

        /// <summary>
        /// Checks whether a give password (string as UTF8 byte array) is strong enough.
        /// </summary>
        /// <param name="password">The password to check (a string encoded into a UTF8 byte array).</param>
        /// <returns><c>true</c> if the password is OK; <c>false</c> if the password is too weak.</returns>
        public bool IsPasswordStrongEnough(byte[] password)
        {
            return assessPasswordStrengthDelegate(password, (ulong)password.LongLength) == 0;
        }

        /// <summary>
        /// Checks whether a give password is strong enough.
        /// </summary>
        /// <param name="password">The password to check.</param>
        /// <returns><c>true</c> if the password is OK; <c>false</c> if the password is too weak.</returns>
        public bool IsPasswordStrongEnough(string password)
        {
            return IsPasswordStrongEnough(Encoding.UTF8.GetBytes(password));
        }

        /// <summary>
        /// Gets the current pwcrypt version number (numeric).
        /// </summary>
        /// <returns>Pwcrypt version number (32-bit unsigned integer).</returns>
        public uint GetVersionNumber()
        {
            return getVersionNumberDelegate();
        }

        /// <summary>
        /// Gets the current Argon2 version number used by pwcrypt (numeric).
        /// </summary>
        /// <returns>Argon2 version number (32-bit unsigned integer).</returns>
        public uint GetArgon2VersionNumber()
        {
            return getArgon2VersionNumberDelegate();
        }

        /// <summary>
        /// Gets the current pwcrypt version number as a nicely-formatted, human-readable string.
        /// </summary>
        /// <returns>Pwcrypt version number (MAJOR.MINOR.PATCH)</returns>
        public string GetVersionNumberString()
        {
            IntPtr str = getVersionNumberStringDelegate();
            return Marshal.PtrToStringAnsi(str);
        }

        /// <summary>
        /// Encrypts an input string of data symmetrically with a password. <para> </para>
        /// The password string is fed into a customizable amount of Argon2id iterations to derive a 256-bit symmetric key, with which the input will be encrypted and written into the output buffer.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="compress">Should the input data be compressed before being encrypted? Pass <c>0</c> for no compression, or a compression level from <c>1</c> to <c>9</c> to pass to the deflate algorithm (<c>6</c> is a healthy default value to use for this).</param>
        /// <param name="password">The encryption password.</param>
        /// <param name="argon2CostT">The Argon2 time cost parameter (number of iterations) to use for deriving the symmetric encryption key. Pass <c>0</c> to use the default value.</param>
        /// <param name="argon2CostM">The Argon2 memory cost parameter (in KiB) to use for key derivation.  Pass <c>0</c> to use the default value.</param>
        /// <param name="argon2Parallelism">Degree of parallelism to use when deriving the symmetric encryption key from the password with Argon2 (number of parallel threads).  Pass <c>0</c> to use the default value.</param>
        /// <param name="algo">Which encryption algo to use (see the top of the pwcrypt.h header file for more infos).</param>
        /// <param name="outputBase64">Should the encrypted output bytes be base64-encoded for easy textual transmission (e.g. email)?</param>
        /// <returns>The encrypted data bytes; or <c>null</c> if encryption failed.</returns>
        public byte[] Encrypt(byte[] data, uint compress, byte[] password, uint argon2CostT, uint argon2CostM, uint argon2Parallelism, uint algo, bool outputBase64)
        {
            int r = encryptDelegate(data, (ulong)data.LongLength, compress, password, (ulong)password.LongLength, argon2CostT, argon2CostM, argon2Parallelism, algo, out IntPtr output, out ulong outputLength, (uint)(outputBase64 ? 1 : 0));
            if (r != 0)
            {
                return null;
            }

            byte[] o = MarshalReadBytes(output, outputLength);

            freeDelegate(output);
            return o;
        }

        /// <summary>
        /// Decrypts a byte array that was encrypted using <see cref="Encrypt"/>. <para> </para>
        /// </summary>
        /// <param name="encryptedData">The ciphertext to decrypt.</param>
        /// <param name="password">The decryption password.</param>
        /// <returns>The decrypted data bytes; or <c>null</c> if decryption failed.</returns>
        public byte[] Decrypt(byte[] encryptedData, byte[] password)
        {
            int r = decryptDelegate(encryptedData, (ulong)encryptedData.LongLength, password, (ulong)password.LongLength, out IntPtr output, out ulong outputLength);
            if (r != 0)
            {
                return null;
            }

            byte[] o = MarshalReadBytes(output, outputLength);

            freeDelegate(output);
            return o;
        }

        /// <summary>
        /// Frees unmanaged resources (unloads the shared lib/dll).
        /// </summary>
        public void Dispose()
        {
            DisableConsoleLogging();
            loadUtils.FreeLibrary(lib);
        }
    }

    //  --------------------------------------------------------------------
    //  ------------------------------> DEMO <------------------------------
    //  --------------------------------------------------------------------

    /// <summary>
    /// Just an example console program. Don't copy this.
    /// </summary>
    internal static class Program
    {
        private static void Main()
        {
            using var pwcrypt = new PwcryptSharpContext();

            pwcrypt.EnableConsoleLogging();
            Console.WriteLine("Allow fprintf: " + pwcrypt.IsConsoleLoggingEnabled() + Environment.NewLine);

            Console.WriteLine("File size of the executing assembly: " + pwcrypt.GetFilesize(Assembly.GetExecutingAssembly().Location) + Environment.NewLine);

            byte[] rnd = pwcrypt.GetRandomBytes(32);
            Console.WriteLine("Here's 32 random bytes (Base64-encoded): " + Convert.ToBase64String(rnd) + Environment.NewLine);

            Console.WriteLine($"Pwcrypt Version Number: {pwcrypt.GetVersionNumberString()} ({pwcrypt.GetVersionNumber()})" + Environment.NewLine);
            Console.WriteLine($"Argon2 version number used by this version of pwcrypt: {pwcrypt.GetArgon2VersionNumber()}" + Environment.NewLine);

            Console.WriteLine("Is the password \"test test\" strong enough? -> " + pwcrypt.IsPasswordStrongEnough("test") + Environment.NewLine);
            Console.WriteLine("Is the password \"TEst/_123.!\" strong enough? -> " + pwcrypt.IsPasswordStrongEnough("TEstTeSt_123.!") + Environment.NewLine);

            string testPw = "jfDeu48,-.329!=+3mffSyA-gfERQsdj";

            string testString = "ENCRYPT ME HARDER ayye ;DDD 1337 ARGH argon2 YEA __ " +
                                "Here's some random text to demonstrate compression+encryption: \n" +
                                "Lorem Ipsum is simply dummy text of the printing and typesetting industry. " +
                                "Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, " +
                                "when an unknown printer took a galley of type and scrambled it to make a type specimen book. " +
                                "It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. " +
                                "It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, " +
                                "and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum. " +
                                "Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, " +
                                "making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, " +
                                "looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, " +
                                "discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of \"de Finibus Bonorum et Malorum\" (The Extremes of Good and Evil) " +
                                "by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. " +
                                "The first line of Lorem Ipsum, \"Lorem ipsum dolor sit amet..\", comes from a line in section 1.10.32." +
                                "\n (source: https://www.lipsum.com)";

            byte[] encrypted = pwcrypt.Encrypt(Encoding.UTF8.GetBytes(testString), 9, Encoding.UTF8.GetBytes(testPw), 0, 0, 0, 0, true);
            byte[] decrypted = pwcrypt.Decrypt(encrypted, Encoding.UTF8.GetBytes(testPw));

            Console.WriteLine("Test string: " + testString + Environment.NewLine);

            if (encrypted != null)
                Console.WriteLine($"Encrypted:   {Encoding.UTF8.GetString(encrypted)}\n");

            if (decrypted != null)
                Console.WriteLine($"Decrypted:   {Encoding.UTF8.GetString(decrypted)}\n");

            pwcrypt.DisableConsoleLogging();
            Console.WriteLine("Allow fprintf: " + pwcrypt.IsConsoleLoggingEnabled());
        }
    }
}