using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretKeyAuthTest
    {
        [TestCategory("SecretKeyAuth")]
        [TestMethod]
        public void SecretKeyAuthGenerateKeyTest()
        {
            Assert.AreEqual(32, SecretKeyAuth.GenerateKey().Length);
        }

        [TestCategory("SecretKeyAuth")]
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

        [TestCategory("SecretKeyAuth")]
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

        [TestCategory("SecretKeyAuth")]
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

        [TestCategory("SecretKeyAuth")]
        [TestMethod]
        public void HmacSha256Test()
        {
            var key = SecretKeyAuth.GenerateKey();
            string message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var sig1 = SecretKeyAuth.SignHmacSha256(message, key);
            var sig2 = SecretKeyAuth.SignHmacSha256(byteMessage, key);

            // Verify the overload works
            Assert.AreEqual(Convert.ToBase64String(sig1), Convert.ToBase64String(sig2));

            var result = SecretKeyAuth.VerifyHmacSha256(message, sig1, key);
            Assert.IsTrue(result);
            result = SecretKeyAuth.VerifyHmacSha256(message, sig2, key);
            Assert.IsTrue(result);

            result = SecretKeyAuth.VerifyHmacSha256(byteMessage, sig1, key);
            Assert.IsTrue(result);
            result = SecretKeyAuth.VerifyHmacSha256(byteMessage, sig2, key);
            Assert.IsTrue(result);
        }

        [TestCategory("SecretKeyAuth")]
        [TestMethod]
        public void HmacSha512Test()
        {
            var key = SecretKeyAuth.GenerateKey();
            string message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var sig1 = SecretKeyAuth.SignHmacSha512(message, key);
            var sig2 = SecretKeyAuth.SignHmacSha512(byteMessage, key);

            // Verify the overload works
            Assert.AreEqual(Convert.ToBase64String(sig1), Convert.ToBase64String(sig2));

            var result = SecretKeyAuth.VerifyHmacSha512(message, sig1, key);
            Assert.IsTrue(result);
            result = SecretKeyAuth.VerifyHmacSha512(message, sig2, key);
            Assert.IsTrue(result);

            result = SecretKeyAuth.VerifyHmacSha512(byteMessage, sig1, key);
            Assert.IsTrue(result);
            result = SecretKeyAuth.VerifyHmacSha512(byteMessage, sig2, key);
            Assert.IsTrue(result);
        }
    }
}