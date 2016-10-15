using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretKeyAuthTest
    {
        [TestMethod]
        public void SecretKeyAuthGenerateKeyTest()
        {
            Assert.AreEqual(32, SecretKeyAuth.GenerateKey().Length);
        }

        [TestMethod]
        public void SecretKeyAuthSignTest()
        {
            // Test signing given a known key and signature generated from libsodium
            byte[] key = Convert.FromBase64String("wYSsnapy7G9F+NTo/bVvIpnRv/ULd97XSMPLoe4+abM=");
            String expectedSignature = "hQ4vOFX+pPJNhXxnbMfzAtLjSVeRBBGCOIjlNoIWvzA=";
            String message = "Hello, World!";
            byte[] signature = SecretKeyAuth.Sign(System.Text.Encoding.UTF8.GetBytes(message), key);

            Assert.AreEqual(32, signature.Length);
            Assert.AreEqual(expectedSignature, Convert.ToBase64String(signature));

            signature = SecretKeyAuth.Sign(message, key);
            Assert.AreEqual(32, signature.Length);
            Assert.AreEqual(expectedSignature, Convert.ToBase64String(signature));
        }

        [TestMethod]
        public void SecretKeyAuthOpenTest()
        {
            var key = Convert.FromBase64String("wYSsnapy7G9F+NTo/bVvIpnRv/ULd97XSMPLoe4+abM=");
            byte[] signature = Convert.FromBase64String("hQ4vOFX+pPJNhXxnbMfzAtLjSVeRBBGCOIjlNoIWvzA=");
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            bool result = SecretKeyAuth.Verify(byteMessage, signature, key);
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void SecretKeyAuthSignAndVerifyTest()
        {
            byte[] key = SecretKeyAuth.GenerateKey();
            String message = "Hello, World!";

            byte[] signature = SecretKeyAuth.Sign(System.Text.Encoding.UTF8.GetBytes(message), key);
            Assert.AreEqual(32, signature.Length);
            bool verification = SecretKeyAuth.Verify(System.Text.Encoding.UTF8.GetBytes(message), signature, key);
            Assert.IsTrue(verification);

            signature = SecretKeyAuth.Sign(message, key);
            Assert.AreEqual(32, signature.Length);
            verification = SecretKeyAuth.Verify(message, signature, key);
            Assert.IsTrue(verification);
        }
    }
}