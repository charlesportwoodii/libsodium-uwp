using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Windows.Security.Cryptography.Core;

namespace Test
{
    [TestClass]
    public class KDFTest
    {
        [TestMethod]
        public void PBKDF2Test()
        {
            // Directly compare to other known pbkdf2 implementations with known value and output
            // Output is derived from php:hash_pbkdf2
            var salt = Convert.FromBase64String("iszDKigtU8NhOSY5Dz8m3uw2Bpdcyjc436kLiqTYjxU=");
            var expected = Convert.FromBase64String("PFjtIDyW8JV9IZ7D19EGuUlSTLvJePc+PfeZEDYSM88=");
            var password = "correct horse battery staple";

            var result = Sodium.KDF.PBKDF2(password, salt, 10000, 32, KeyDerivationAlgorithmNames.Pbkdf2Sha256);
            Assert.AreEqual(expected.ToString(), result.ToString());
        }


        // RFC6070 outlines the following test cases
        // https://www.ietf.org/rfc/rfc6070.txt
        [TestMethod]
        public void RFC6070Test()
        {
            var p = "password";
            var s = System.Text.Encoding.ASCII.GetBytes("salt");
            var c = 1;
            var dkLen = 20;

            var result = Sodium.KDF.PBKDF2(p, s, c, dkLen, KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            var expected = new byte[]
            {
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
                0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
                0x2f, 0xe0, 0x37, 0xa6
            };

            Assert.AreEqual(expected.ToString(), result.ToString());

            p = "password";
            s = System.Text.Encoding.ASCII.GetBytes("salt");
            c = 2;
            dkLen = 20;

            result = Sodium.KDF.PBKDF2(p, s, c, dkLen, KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            expected = new byte[]
            {
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
                0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
                0xd8, 0xde, 0x89, 0x57
            };

            Assert.AreEqual(expected.ToString(), result.ToString());

            p = "password";
            s = System.Text.Encoding.ASCII.GetBytes("salt");
            c = 4096;
            dkLen = 20;

            result = Sodium.KDF.PBKDF2(p, s, c, dkLen, KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            expected = new byte[]
            {
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
                0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
                0x65, 0xa4, 0x29, 0xc1
            };

            Assert.AreEqual(expected.ToString(), result.ToString());

            p = "password";
            s = System.Text.Encoding.ASCII.GetBytes("salt");
            c = 16777216;
            dkLen = 20;

            result = Sodium.KDF.PBKDF2(p, s, c, dkLen, KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            expected = new byte[]
            {
                0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
                0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
                0x26, 0x34, 0xe9, 0x84
            };

            Assert.AreEqual(expected.ToString(), result.ToString());

            p = "passwordPASSWORDpassword";
            s = System.Text.Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
            c = 4096;
            dkLen = 25;

            result = Sodium.KDF.PBKDF2(p, s, c, dkLen, KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            expected = new byte[]
            {
                0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
                0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
                0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
                0x38
            };

            Assert.AreEqual(expected.ToString(), result.ToString());

            p = "pass\0word";
            s = System.Text.Encoding.ASCII.GetBytes("sa\0lt");
            c = 4096;
            dkLen = 16;

            result = Sodium.KDF.PBKDF2(p, s, c, dkLen, KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            expected = new byte[]
            {
                0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
                0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
            };

            Assert.AreEqual(expected.ToString(), result.ToString());
        }
    }
}
