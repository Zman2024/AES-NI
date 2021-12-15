using System;
using Crypto = System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace AES_NI
{
    public static unsafe class libaes
    {
        const string LibName = "libaes.dll";

        [DllImport(LibName)]
        public static extern void* ExpandKeyENC_SSE(void* key, void* @out);

        [DllImport(LibName)]
        public static extern void* ExpandKeyENC_AVX(void* key, void* @out);

        [DllImport(LibName)]
        public static extern void* ExpandKeyDEC(void* key, void* @out);

        [DllImport(LibName)]
        public static extern void EncryptSSE(void* plaintext, void* rKeys, void* @out);

        [DllImport(LibName)]
        public static extern void EncryptAVX(void* plaintext, void* rKeys, void* @out);

        [DllImport(LibName)]
        public static extern void Decrypt(void* cipertext, void* rKeys, void* @out);
    }

    // yes, im using malloc/free in C#. what of it?
    public static unsafe class msvcrt
    {
        const string LibName = "msvcrt.dll";

        [DllImport(LibName)]
        public static extern void* malloc(nint size);

        [DllImport(LibName)]
        public static extern void* calloc(nint count, nint size);

        [DllImport(LibName)]
        public static extern void free(void* ptr);

        [DllImport(LibName)]
        public static extern void memcpy(void* dest, void* src, nint size);
    }

}
