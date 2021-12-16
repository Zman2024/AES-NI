using System;
using Crypto = System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Diagnostics;
using static System.Console;
using static global::msvcrt;

namespace AES_NI
{
    public unsafe struct V128 
    {
        fixed byte data[16];
        public const int Length = 16;

        public static implicit operator Vector128<byte>(V128 @this) => @this;
        public static implicit operator Vector128<short>(V128 @this) => @this;
        public static implicit operator Vector128<int> (V128 @this) => @this;
        public static implicit operator Vector128<long>(V128 @this) => @this;

        public static implicit operator V128(Vector128<byte> @this) => @this;
        public static implicit operator V128(Vector128<short> @this) => @this;
        public static implicit operator V128(Vector128<int> @this) => @this;
        public static implicit operator V128(Vector128<long> @this) => @this;

        public static implicit operator V128(byte[] @this)
        {
            fixed(byte* ptr = @this)
            {
                return *(V128*)ptr;
            }
        }
        public static implicit operator V128(byte* @this) => *(V128*)@this;

        public static implicit operator byte* (V128 @this) => (byte*)&@this;

        public byte this[int index]
        {
            get => data[index];
            set => data[index] = value;
        }

        public override string ToString()
        {
            string result = "[";
            for (int index = 0; index < Length; index++)
            {
                if (data[index] < 0x10) result += "0" + data[index].ToString("X");
                else result += data[index].ToString("X");
                if (index + 1 != Length) result += ", ";
            }
            return result + "]";
        }

        public static bool operator == (V128 left, V128 right)
        {
            return (((ulong*)left.data)[0] == ((ulong*)right.data)[0]) & (((ulong*)left.data)[1] == ((ulong*)right.data)[1]);
        }

        public static bool operator !=(V128 left, V128 right)
        {
            return !(left == right);
        }

        public override bool Equals(object cmp)
        {
            if (cmp.GetType() != typeof(V128)) return false;

            return (V128)cmp == this;
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

    }

    public unsafe struct V256 
    {
        public const int Length = 32;
        fixed byte data[Length];

        public static implicit operator Vector128<byte>(V256 @this) => @this;
        public static implicit operator Vector128<short>(V256 @this) => @this;
        public static implicit operator Vector128<int>(V256 @this) => @this;
        public static implicit operator Vector128<long>(V256 @this) => @this;

        public static implicit operator V256(Vector128<byte> @this) => @this;
        public static implicit operator V256(Vector128<short> @this) => @this;
        public static implicit operator V256(Vector128<int> @this) => @this;
        public static implicit operator V256(Vector128<long> @this) => @this;

        public static implicit operator Vector256<byte>(V256 @this) => @this;
        public static implicit operator Vector256<short>(V256 @this) => @this;
        public static implicit operator Vector256<int>(V256 @this) => @this;
        public static implicit operator Vector256<long>(V256 @this) => @this;

        public static implicit operator V256(Vector256<byte> @this) => @this;
        public static implicit operator V256(Vector256<short> @this) => @this;
        public static implicit operator V256(Vector256<int> @this) => @this;
        public static implicit operator V256(Vector256<long> @this) => @this;

        public static implicit operator V256(byte[] @this)
        {
            fixed (byte* ptr = @this)
            {
                return *(V256*)ptr;
            }
        }

        public static implicit operator V256(byte* @this) => *(V256*)@this;
        public static implicit operator byte*(V256 @this) => (byte*)&@this;

        public byte this[int index]
        {
            get => data[index];
            set => data[index] = value;
        }

        public override string ToString()
        {
            string result = "[";
            for (int index = 0; index < Length; index++)
            {
                if (data[index] < 0x10) result += "0" + data[index].ToString("X");
                else result += data[index].ToString("X");
                if (index + 1 != Length) result += ", ";
            }
            return result + "]";
        }

    }

    public static unsafe class aes_ni
    {
        static class Test
        {
            public static byte[] TestKey = new byte[] 
            { 
                0x08, 0x09, 0x0A, 0x0B, 
                0x0D, 0x0E, 0x0F, 0x10, 
                0x12, 0x13, 0x14, 0x15, 
                0x17, 0x18, 0x19, 0x1A, 
                0x1C, 0x1D, 0x1E, 0x1F, 
                0x21, 0x22, 0x23, 0x24, 
                0x26, 0x27, 0x28, 0x29, 
                0x2B, 0x2C, 0x2D, 0x2E 
            };
            public static byte[] TestPlaintext = new byte[] 
            { 
                0x06, 0x9A, 0x00, 0x7F, 
                0xC7, 0x6A, 0x45, 0x9F, 
                0x98, 0xBA, 0xF9, 0x17, 
                0xFE, 0xDF, 0x95, 0x21 
            };
            public static byte[] TestExpectedOutput = new byte[]
            { 
                0x08, 0x0e, 0x95, 0x17, 
                0xeb, 0x16, 0x77, 0x71, 
                0x9a, 0xcf, 0x72, 0x80, 
                0x86, 0x04, 0x0a, 0xe3 
            };

            public const nint RoundKeyBufferSize = 0x10 * 15;
            public const nint PerformanceAllocationSize = 1000000000;

            public static bool PerformIntegrityTestSSE()
            {
                V256 Key = TestKey;
                V128* rKeys = (V128*)calloc(1, RoundKeyBufferSize);
                V128 Plaintext = TestPlaintext;
                V128 resultBuffer = new V128();

                libaes.SSE.ExpandKey(&Key, rKeys, true);
                libaes.SSE.Encrypt(&Plaintext, rKeys, &resultBuffer);

                if (resultBuffer != TestExpectedOutput)
                {
                    free(rKeys);
                    return false;
                }

                libaes.SSE.ExpandKey(&Key, rKeys, false);
                libaes.SSE.Decrypt(&resultBuffer, rKeys, &resultBuffer);

                free(rKeys);

                return resultBuffer == TestPlaintext;
            }

            public static bool PerformIntegrityTestAVX()
            {
                V256 Key = TestKey;
                V128* rKeys = (V128*)calloc(1, RoundKeyBufferSize);
                V128 Plaintext = TestPlaintext;
                V128 resultBuffer = new V128();

                libaes.AVX.ExpandKey(&Key, rKeys, true);
                libaes.AVX.Encrypt(&Plaintext, rKeys, &resultBuffer);

                if (resultBuffer != TestExpectedOutput)
                {
                    free(rKeys);
                    return false;
                }

                libaes.AVX.ExpandKey(&Key, rKeys, false);
                libaes.AVX.Decrypt(&resultBuffer, rKeys, &resultBuffer);

                free(rKeys);

                return resultBuffer == TestPlaintext;
            }

            // Returns the number of seconds per GB of data
            public static double PerformSpeedTestSSE()
            {
                byte* buffer = (byte*)malloc(PerformanceAllocationSize);
                byte* rKeys = (byte*)malloc(RoundKeyBufferSize);

                nint x = 0x00;
                var sw = Stopwatch.StartNew();
                while (x < PerformanceAllocationSize)
                {
                    libaes.SSE.Encrypt(buffer + x, rKeys, buffer + x);
                    x += 0x10;
                }
                sw.Stop();

                free(buffer);
                free(rKeys);

                return sw.Elapsed.TotalSeconds;
            }

            // Returns the number of seconds per GB of data
            public static double PerformSpeedTestAVX()
            {
                byte* buffer = (byte*)malloc(PerformanceAllocationSize);
                byte* rKeys = (byte*)malloc(RoundKeyBufferSize);

                nint x = 0x00;
                var sw = Stopwatch.StartNew();
                while (x < PerformanceAllocationSize)
                {
                    libaes.AVX.Encrypt(buffer + x, rKeys, buffer + x);
                    x += 0x10;
                }
                sw.Stop();

                free(buffer);
                free(rKeys);

                return sw.Elapsed.TotalSeconds;
            }

        }

        static double TestSSE(uint nRounds)
        {
            double avgSSESpeed = 0;

            WriteLine($"Performing {nRounds} rounds of SSE... (1GB)");
            for (int x = 0; x < nRounds; x++)
            {

                double SSESpeed = (Test.PerformanceAllocationSize / Test.PerformSpeedTestSSE()) / Test.PerformanceAllocationSize;
                WriteLine($"SSE Speed: {Math.Round(SSESpeed, 3)} GB/S");
                avgSSESpeed += SSESpeed;
            }

            return avgSSESpeed / nRounds;
        }

        static double TestAVX(uint nRounds)
        {
            double avgAVXSpeed = 0;

            WriteLine($"Performing {nRounds} rounds of AVX... (1GB)");
            for (int x = 0; x < nRounds; x++)
            {
                double AVXSpeed = (Test.PerformanceAllocationSize / Test.PerformSpeedTestAVX()) / Test.PerformanceAllocationSize;
                WriteLine($"AVX Speed: {Math.Round(AVXSpeed, 3)} GB/S");
                avgAVXSpeed += AVXSpeed;
            }

            return avgAVXSpeed / nRounds;
        }

        public static int Main(string[] args)
        {
            if (!Aes.IsSupported)
            {
                WriteLine("AES instructions not supported on this machine!");
                ReadLine();
                return -1;
            }
            if (!Avx2.IsSupported)
            {
                WriteLine("AVX2 instructions not supported on this machine!");
                ReadLine();
                return -1;
            }

            WriteLine($"AVX Integrity: {Test.PerformIntegrityTestAVX()}");
            WriteLine($"SSE Integrity: {Test.PerformIntegrityTestSSE()}");

            WriteLine();
            double avgAVXSpeed = TestAVX(0x10);
            WriteLine();
            double avgSSESpeed = TestSSE(0x10);
            WriteLine();

            WriteLine($"Average AVX Speed: {Math.Round(avgAVXSpeed, 3)} GB/S");
            WriteLine($"Average SSE Speed: {Math.Round(avgSSESpeed, 3)} GB/S");

            WriteLine();

            Write("Press any key to continue...");
            ReadKey();

            return 0;
        }

    }
}
