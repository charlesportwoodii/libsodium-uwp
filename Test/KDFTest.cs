using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Windows.Security.Cryptography.Core;

namespace Test
{
    [TestClass]
    public class KDFTest
    {
        [TestCategory("PBKDF2")]
        [TestMethod]
        public void PBKDF2Test()
        {
            // Directly compare to other known pbkdf2 implementations with known value and output
            // Output is derived from php:hash_pbkdf2
            var salt = Convert.FromBase64String("iszDKigtU8NhOSY5Dz8m3uw2Bpdcyjc436kLiqTYjxU=");
            var expected = Convert.FromBase64String("PFjtIDyW8JV9IZ7D19EGuUlSTLvJePc+PfeZEDYSM88=");
            var password = "correct horse battery staple";

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha256, password, salt, 10000, 32);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        // RFC6070 outlines the following test cases
        // https://www.ietf.org/rfc/rfc6070.txt
        [TestCategory("PBKDF2")]
        [TestMethod]
        public void RFC6070A1Test()
        {
            var p = "password";
            var s = System.Text.Encoding.ASCII.GetBytes("salt");
            var c = 1;
            var dkLen = 20;

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            var expected = new byte[]
            {
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
                0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
                0x2f, 0xe0, 0x37, 0xa6
            };

            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        [TestCategory("PBKDF2")]
        [TestMethod]
        public void RFC6070A2Test()
        {
            var p = "password";
            var s = System.Text.Encoding.ASCII.GetBytes("salt");
            var c = 2;
            var dkLen = 20;

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            var expected = new byte[]
            {
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
                0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
                0xd8, 0xde, 0x89, 0x57
            };

            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        [TestCategory("PBKDF2")]
        [TestMethod]
        public void RFC6070A3Test()
        {
            var p = "password";
            var s = System.Text.Encoding.ASCII.GetBytes("salt");
            var c = 4096;
            var dkLen = 20;

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            var expected = new byte[]
            {
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
                0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
                0x65, 0xa4, 0x29, 0xc1
            };

            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        [TestCategory("PBKDF2")]
        [TestMethod]
        public void RFC6070A4Test()
        {
            var p = "password";
            var s = System.Text.Encoding.ASCII.GetBytes("salt");
            var c = 16777216;
            var dkLen = 20;

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            var expected = new byte[]
            {
                0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
                0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
                0x26, 0x34, 0xe9, 0x84
            };

            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        [TestCategory("PBKDF2")]
        [TestMethod]
        public void RFC6070A5Test()
        {
            var p = "passwordPASSWORDpassword";
            var s = System.Text.Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
            var c = 4096;
            var dkLen = 25;

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            var expected = new byte[]
            {
                0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
                0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
                0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
                0x38
            };

            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        [TestCategory("PBKDF2")]
        [TestMethod]
        public void RFC6070A6Test()
        {
            var p = "pass\0word";
            var s = System.Text.Encoding.ASCII.GetBytes("sa\0lt");
            var c = 4096;
            var dkLen = 16;

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            var expected = new byte[]
            {
                0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
                0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
            };

            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        [TestCategory("HKDF")]
        [TestMethod]
        public void HKDFTest()
        {
            // salt and ikm are 32 random bytes, base46 encoded
            var salt = Convert.FromBase64String("hsXKrSfNu/9qMc3j6sohQuSymsrkL6URwRkthQM4+yI=");
            var ikm = Convert.FromBase64String("XC+Ph8miNDofAtYDrsyOoPFN6ofTmmA6z+BsjNgjIC0=");
        
            // The expected result is calculated from a known working HKDF implementation, base64 encoded
            var expected = Convert.FromBase64String("uP5Uvdmamdg1uzEbh/Tvg+BYsHXHcwAg/VRGJ5yPj3Y=");
            var algorithm = MacAlgorithmNames.HmacSha256;
            var authInfo = System.Text.Encoding.UTF8.GetBytes("test");

            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, authInfo, 32);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));

            // This should be the same, because outputLength will transform to 32
            result = Sodium.KDF.HKDF(algorithm, ikm, salt, authInfo, 0);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        // Test vectors derived from https://tools.ietf.org/html/rfc5869
        // NOTE: values are base64 encodings of their hexidecimal representation in the RFC.
        // This is done to reduce typing. The values are equivalent
        [TestCategory("HKDF")]
        [TestMethod]
        public void RFC5869A1Test()
        {
            var ikm = Convert.FromBase64String("CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==");
            var salt = Convert.FromBase64String("AAECAwQFBgcICQoLDA==");
            var info = Convert.FromBase64String("8PHy8/T19vf4+Q==");
            var expected = Convert.FromBase64String("PLJfJfqs1XqQQ09k0DYvKi0tCpDPGlpMXbAtVuzExb80AHII1biHGFhl");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha256;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == l);
        }

        [TestCategory("HKDF")]
        [TestMethod]
        public void RFC5869A2Test()
        {
            var ikm = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk8=");
            var salt = Convert.FromBase64String("YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq8=");
            var info = Convert.FromBase64String("sLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8=");
            var expected = Convert.FromBase64String("sR45jcgDJ6HI5/eMWWpJNE8BLtotTvrYoFDMTBmvqXxZBFqZyseCcnHLQcZeWQ4J2jJ1YAwvCbg2d5OprKPbccwwxYF57D6HwUwB1cHzQ08dhw==");
            int l = 82;

            var algorithm = MacAlgorithmNames.HmacSha256;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == l);
        }

        [TestCategory("HKDF")]
        [TestMethod]
        public void RFC5869A3Test()
        {
            var ikm = Convert.FromBase64String("CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==");
            var salt = new byte[] { };
            var info = new byte[] { };
            var expected = Convert.FromBase64String("jaTndaVjwY9xX4AqBjxaMbihH1xe4Yeew0VOXzxzjS2dIBOV+qS2GpbI");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha256;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == l);
        }

        [TestCategory("HKDF")]
        [TestMethod]
        public void RFC5869A4Test()
        {
            var ikm = Convert.FromBase64String("CwsLCwsLCwsLCws=");
            var salt = Convert.FromBase64String("AAECAwQFBgcICQoLDA==");
            var info = Convert.FromBase64String("8PHy8/T19vf4+Q==");
            var expected = Convert.FromBase64String("CFoB6hsQ82kzBotW76WtgaTxS4IvWwkVaKnN1PFV/aLCLkIkeNMF8/iW");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha1;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == l);
        }

        [TestCategory("HKDF")]
        [TestMethod]
        public void RFC5869A5Test()
        {
            var ikm = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk8=");
            var salt = Convert.FromBase64String("YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq8=");
            var info = Convert.FromBase64String("sLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8=");
            var expected = Convert.FromBase64String("C9dwp00RYPfJ8SzVkSoG6/9q3K6JnZIZH+QwVnO6L/6Po/Gk5a158/M0s7ICshc8SG6jfOPTl+0DTH+d/rFcXpJzNtBEH0xDAOLP8NCQC1LTtA==");
            int l = 82;

            var algorithm = MacAlgorithmNames.HmacSha1;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.IsTrue(result.Length == l);
        }

        [TestCategory("HKDF")]
        [TestMethod]
        public void RFC5869A6Test()
        {
            var ikm = Convert.FromBase64String("CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==");
            var salt = new byte[] { };
            var info = new byte[] { };
            var expected = Convert.FromBase64String("CsGvcAKz12HR5VKY2p0FBrmuUgVyIKMG4Htrh+jfIdDqAAM94DmE00kY");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha1;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == l);
        }

        [TestCategory("HKDF")]
        [TestMethod]
        public void RFC5869A7Test()
        {
            var ikm = Convert.FromBase64String("DAwMDAwMDAwMDAwMDAwMDAwMDAwMDA==");
            var salt = new byte[] { };
            var info = new byte[] { };
            var expected = Convert.FromBase64String("LJERcgTXRfNQDWNqYvZPCrO65UiqU9QjsNHyfrum9eVnOggdcMznrPxI");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha1;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == l);
        }

        [TestCategory("HSalsa20")]
        [TestMethod]
        public void HSalsa20Test()
        {
            var shared = new byte[]
            {
                 0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
                ,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
                ,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
                ,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
            };

            var zero = new byte[32];

            var c = new byte[]
            {
                 0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x33
                ,0x32,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b
            };

            var expected = new byte[]
            {
                 0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
                ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
                ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
                ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
            };

            var result = Sodium.KDF.HSalsa20(zero, shared, c);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == 32);

            var nonceprefix = new byte[]
            {
                 0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
                ,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
            };

            c = new byte[]  {
                 0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x33
                ,0x32,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b
            };

            expected = new byte[]
            {
                 0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
                ,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
                ,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
                ,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4
            };

            result = Sodium.KDF.HSalsa20(nonceprefix, result, c);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
            Assert.IsTrue(result.Length == 32);
        }

        [TestCategory("Argon2i")]
        [TestMethod]
        public void Argon2iTest()
        {
            string password = "correct horse battery staple";
            var options = PasswordHash.CreateOptions(1 << 8, 3);

            var result = Sodium.KDF.Argon2i(password, options);
            Assert.AreEqual(32, result.Length);

            var salt = Sodium.Core.GetRandomBytes(16);
            result = Sodium.KDF.Argon2i(password, salt, options);
            Assert.AreEqual(32, result.Length);
        }

        [TestCategory("Scrypt")]
        [TestMethod]
        public void ScryptTest()
        {
            string password = "correct horse battery staple";
            var options = PasswordHash.CreateOptions(1 << 8, 3);

            var result = Sodium.KDF.Scrypt(password, options);
            Assert.AreEqual(32, result.Length);

            var salt = Sodium.Core.GetRandomBytes(32);
            result = Sodium.KDF.Scrypt(password, salt, options);
            Assert.AreEqual(32, result.Length);
        }
    }
}
