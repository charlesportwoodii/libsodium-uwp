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

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha256, password, salt, 10000, 32);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
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

            var result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            var expected = new byte[]
            {
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
                0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
                0x2f, 0xe0, 0x37, 0xa6
            };
            
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));

            p = "password";
            s = System.Text.Encoding.ASCII.GetBytes("salt");
            c = 2;
            dkLen = 20;

            result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            expected = new byte[]
            {
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
                0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
                0xd8, 0xde, 0x89, 0x57
            };
            
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));

            p = "password";
            s = System.Text.Encoding.ASCII.GetBytes("salt");
            c = 4096;
            dkLen = 20;

            result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            expected = new byte[]
            {
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
                0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
                0x65, 0xa4, 0x29, 0xc1
            };
            
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));

            p = "password";
            s = System.Text.Encoding.ASCII.GetBytes("salt");
            c = 16777216;
            dkLen = 20;

            result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            expected = new byte[]
            {
                0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
                0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
                0x26, 0x34, 0xe9, 0x84
            };
            
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));

            p = "passwordPASSWORDpassword";
            s = System.Text.Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
            c = 4096;
            dkLen = 25;

            result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            expected = new byte[]
            {
                0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
                0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
                0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
                0x38
            };
            
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));

            p = "pass\0word";
            s = System.Text.Encoding.ASCII.GetBytes("sa\0lt");
            c = 4096;
            dkLen = 16;

            result = Sodium.KDF.PBKDF2(KeyDerivationAlgorithmNames.Pbkdf2Sha1, p, s, c, dkLen);
            expected = new byte[]
            {
                0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
                0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
            };
            
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

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
        [TestMethod]
        public void RFC5869A1Test()
        {
            var ikm = Convert.FromBase64String("AAsLCwsLCwsLCwsLCwsLCwsLCwsLCws=");
            var salt = Convert.FromBase64String("AAABAgMEBQYHCAkKCww=");
            var info = Convert.FromBase64String("APDx8vP09fb3+Pk=");
            var expected = Convert.FromBase64String("ADyyXyX6rNV6kENPZNA2LyotLQqQzxpaTF2wLVbsxMW/NAByCNW4hxhYZQ==");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha256;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }
        
        /*
        [TestMethod]
        public void RFC5869A2Test()
        {
            var ikm = Convert.FromBase64String("AAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P");
            var salt = Convert.FromBase64String("AGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6v");
            var info = Convert.FromBase64String("ALCxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/");
            var expected = Convert.FromBase64String("ALEeOY3IAyehyOf3jFlqSTRPAS7aLU762KBQzEwZr6l8WQRamcrHgnJxy0HGXlkOCdoydWAMLwm4NneTqayj23HMMMWBeew+h8FMAdXB80NPHYc=");
            int l = 82;

            var algorithm = MacAlgorithmNames.HmacSha256;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }
        */

        [TestMethod]
        public void RFC5869A3Test()
        {
            var ikm = Convert.FromBase64String("AAsLCwsLCwsLCwsLCwsLCwsLCwsLCws=");
            var salt = new byte[] { };
            var info = new byte[] { };
            var expected = Convert.FromBase64String("AI2k53WlY8GPcV+AKgY8WjG4oR9cXuGHnsNFTl88c40tnSATlfqkthqWyA==");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha256;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        [TestMethod]
        public void RFC5869A4Test()
        {
            var ikm = Convert.FromBase64String("AAsLCwsLCwsLCwsL");
            var salt = Convert.FromBase64String("AAABAgMEBQYHCAkKCww=");
            var info = Convert.FromBase64String("APDx8vP09fb3+Pk=");
            var expected = Convert.FromBase64String("AAhaAeobEPNpMwaLVu+lrYGk8UuCL1sJFWipzdTxVf2iwi5CJHjTBfP4lg==");
            int l = 42;

            var algorithm = MacAlgorithmNames.HmacSha256;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }

        /*
        [TestMethod]
        public void RFC5869A5Test()
        {
            var ikm = Convert.FromBase64String("AAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P");
            var salt = Convert.FromBase64String("AGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6v");
            var info = Convert.FromBase64String("ALCxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/");
            var expected = Convert.FromBase64String("AAvXcKdNEWD3yfEs1ZEqBuv/atyuiZ2SGR/kMFZzui/+j6PxpOWtefPzNLOyArIXPEhuo3zj05ftA0x/nf6xXF6SczbQRB9MQwDiz/DQkAtS07Q=");
            int l = 82;

            var algorithm = MacAlgorithmNames.HmacSha1;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
        }
        */

        // Test case A6 and A7 are more or less equivalent since our API doesn't permit NULL values for salt
        [TestMethod]
        public void RFC5869A6Test()
        {
            var ikm = Convert.FromBase64String("AAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw=");
            var salt = new byte[] { };
            var info = new byte[] { };
            var expected = Convert.FromBase64String("ACyREXIE10XzUA1jamL2TwqzuuVIqlPUI7DR8n67pvXlZzoIHXDM56z8SA==");
            int l =42;

            var algorithm = MacAlgorithmNames.HmacSha1;
            var result = Sodium.KDF.HKDF(algorithm, ikm, salt, info, l);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(result));
        }
    }
}
