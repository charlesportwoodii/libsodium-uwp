using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace Test
{
    [TestClass]
    public class PublicKeyAuthTest
    {
        [TestCategory("PublicKeyAuth")]
        [TestMethod]
        public void GenerateKeyPairTest()
        {
            var kp = PublicKeyAuth.GenerateKeyPair();
            Assert.AreEqual(32, kp.Public.Length);
            Assert.AreEqual(64, kp.Secret.Length);
        }

        [TestCategory("PublicKeyAuth")]
        [TestMethod]
        public void GenerateKeyPairFromSeedTest()
        {
            var seed = Core.GetRandomBytes(32);
            var kp = PublicKeyAuth.GenerateKeyPair(seed);
            Assert.AreEqual(32, kp.Public.Length);
            Assert.AreEqual(64, kp.Secret.Length);
        }

        [TestCategory("PublicKeyAuth")]
        [TestMethod]
        public void SignTest()
        {
            var kp = PublicKeyAuth.GenerateKeyPair();
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var signature = PublicKeyAuth.Sign(message, kp.Secret);

            // Test against a seed and expected output generated from libsodium
            var seed = Convert.FromBase64String("zYZceFCtMRu4FAi/a47fN+21396uv/QcUMvi/u08zCw=");
            var expected = Convert.FromBase64String("BlWhHIrosG+Q7jq/lMgxkw79f7dM1x2u+IR6f5nPojaVdaXpUbSpzVSPT238CCDInCnQQ5ueMetEoaXYhET+CEhlbGxvLCBXb3JsZCE=");
            kp = PublicKeyAuth.GenerateKeyPair(seed);
            signature = PublicKeyAuth.Sign(byteMessage, kp.Secret);
            Assert.AreEqual(expected.ToString(), signature.ToString());

            signature = PublicKeyAuth.Sign(message, kp.Secret);
            Assert.AreEqual(expected.ToString(), signature.ToString());
        }

        [TestCategory("PublicKeyAuth")]
        [TestMethod]
        public void VerifyTest()
        {
            var kp = PublicKeyAuth.GenerateKeyPair();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
            var signature = PublicKeyAuth.Sign(message, kp.Secret);
            var verification = PublicKeyAuth.Verify(signature, kp.Public);
            Assert.AreEqual(message.ToString(), verification.ToString());
        }

        [TestCategory("Curve25519 Key Extraction")]
        [TestMethod]
        public void ConvertToCurve25519Test()
        {
            // Keypair seed from libsodium-net
            var keypairSeed = new byte[] {
                0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde,
                0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a, 0xed, 0xae,
                0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe,
                0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa, 0xed, 0xee
              };

            var kp = PublicKeyAuth.GenerateKeyPair(keypairSeed);

            var ed25519Pk = kp.Public;
            var ed25519SkPk = kp.Secret;

            var curve25519Pk = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519Pk);
            var curve25519Sk = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(ed25519SkPk);

            Assert.AreEqual(Convert.ToBase64String(curve25519Pk), "8YFPDo/xBD2KRNJbq/887crmwiw+2qSPhXrnDeK6rlA=");
            Assert.AreEqual(Convert.ToBase64String(curve25519Sk), "gFIDA3bUcRK+f3PtegGSk90SrZELZURVeYtGZ9c94WY=");

            for (var i = 0; i < 500; i++)
            {
                kp = PublicKeyAuth.GenerateKeyPair();
                ed25519Pk = kp.Public;
                ed25519SkPk = kp.Secret;
                curve25519Pk = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519Pk);
                curve25519Sk = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(ed25519SkPk);
                var curve25519Pk2 = ScalarMult.Base(curve25519Sk);

                CollectionAssert.AreEqual(curve25519Pk, curve25519Pk2);
            }
        }

        [TestCategory("Detached PublicKeyAuth")]
        [TestMethod]
        public void DetachedSignTest()
        {
            var kp = PublicKeyAuth.GenerateKeyPair();
            string message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);

            var sig1 = PublicKeyAuth.SignDetached(message, kp.Secret);
            var sig2 = PublicKeyAuth.SignDetached(byteMessage, kp.Secret);

            Assert.AreEqual(Convert.ToBase64String(sig1), Convert.ToBase64String(sig2));
            Assert.AreEqual(64, sig1.Length);
            Assert.AreEqual(64, sig2.Length);

            Assert.IsTrue(PublicKeyAuth.VerifyDetached(sig1, byteMessage, kp.Public));
            Assert.IsTrue(PublicKeyAuth.VerifyDetached(sig1, message, kp.Public));
            Assert.IsTrue(PublicKeyAuth.VerifyDetached(sig2, byteMessage, kp.Public));
            Assert.IsTrue(PublicKeyAuth.VerifyDetached(sig2, message, kp.Public));

            var kp2 = PublicKeyAuth.GenerateKeyPair();
            Assert.IsFalse(PublicKeyAuth.VerifyDetached(sig2, message, kp2.Public));
            Assert.IsFalse(PublicKeyAuth.VerifyDetached(sig2, "Invalid message test", kp.Public));
        }

        [TestCategory("Ed25519 Key Extraction")]
        [TestMethod]
        public void ExtractEd25519SeedFromEd25519SecretKeyTest()
        {
            var kp1 = PublicKeyAuth.GenerateKeyPair();
            var seed = PublicKeyAuth.ExtractEd25519SeedFromEd25519SecretKey(kp1.Secret);
            var kp2 = PublicKeyAuth.GenerateKeyPair(seed);

            Assert.AreEqual(Convert.ToBase64String(kp1.Public), Convert.ToBase64String(kp2.Public));
            Assert.AreEqual(Convert.ToBase64String(kp1.Secret), Convert.ToBase64String(kp2.Secret));
        }

        [TestCategory("Ed25519 Key Extraction")]
        [TestMethod]
        public void ExtractEd25519PublicKeyFromEd25519SecretKeyTest()
        {
            var kp = PublicKeyAuth.GenerateKeyPair();
            var pub = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(kp.Secret);
            Assert.AreEqual(Convert.ToBase64String(kp.Public), Convert.ToBase64String(pub));
        }

        [TestCategory("PublicKeyAuth")]
        [TestMethod]
        public void SignAndVerifyFromMessageTest()
        {
            var kp = PublicKeyAuth.GenerateKeyPair();
            var signature = new PublicKeyAuth();
            IBuffer data = CryptographicBuffer.ConvertStringToBinary("Hello, World!", BinaryStringEncoding.Utf8);
            signature.Append(data);

            var output = signature.GetValueAndReset(kp.Secret);
            Assert.AreEqual(64, output.Length);
            Assert.AreEqual(true, signature.GetValueAndVerify(output, kp.Public));
        }
    }
}
