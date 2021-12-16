using System;
using Crypto = System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

public static unsafe class libaes
{
    const string LibName = "libaes.dll";

    public static unsafe class AVX
    {
        [DllImport(LibName, EntryPoint = "Decrypt_AVX")]
        public static extern void Decrypt(void* ciphertext, void* rKeys, void* @out);

        [DllImport(LibName, EntryPoint = "Encrypt_AVX")]
        public static extern void Encrypt(void* plaintext, void* rKeys, void* @out);

        public static void* ExpandKey(void* key, void* @out, bool encrypting) => encrypting ? ExpandKeyENC(key, @out) : ExpandKeyDEC(key, @out);

        [DllImport(LibName, EntryPoint = "ExpandKeyENC_AVX")]
        public static extern void* ExpandKeyENC(void* key, void* @out);

        [DllImport(LibName, EntryPoint = "ExpandKeyDEC_AVX")]
        public static extern void* ExpandKeyDEC(void* key, void* @out);
    }

    public static unsafe class SSE
    {
        [DllImport(LibName, EntryPoint = "Decrypt_SSE")]
        public static extern void Decrypt(void* ciphertext, void* rKeys, void* @out);

        [DllImport(LibName, EntryPoint = "Encrypt_SSE")]
        public static extern void Encrypt(void* plaintext, void* rKeys, void* @out);

        public static void* ExpandKey(void* key, void* @out, bool encrypting) => encrypting ? ExpandKeyENC(key, @out) : ExpandKeyDEC(key, @out);

        [DllImport(LibName, EntryPoint = "ExpandKeyENC_SSE")]
        public static extern void* ExpandKeyENC(void* key, void* @out);

        [DllImport(LibName, EntryPoint = "ExpandKeyDEC_SSE")]
        public static extern void* ExpandKeyDEC(void* key, void* @out);
    }
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
