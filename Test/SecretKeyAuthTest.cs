using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretKeyAuthTest
    {
        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(32, SecretKeyAuth.GenerateKey().Length);
        }

        [TestMethod]
        public void SignTest()
        {
            // Test signing given a known key and signature generated from libsodium
            byte[] key = Convert.FromBase64String("wYSsnapy7G9F+NTo/bVvIpnRv/ULd97XSMPLoe4+abM=");
            String expectedSignature = "hQ4vOFX+pPJNhXxnbMfzAtLjSVeRBBGCOIjlNoIWvzA=";
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
            byte[] signature = SecretKeyAuth.Sign(message, key);

            Assert.AreEqual(expectedSignature, Convert.ToBase64String(signature));
        }

        [TestMethod]
        public void OpenTest()
        {
            var key = Convert.FromBase64String("wYSsnapy7G9F+NTo/bVvIpnRv/ULd97XSMPLoe4+abM=");
            byte[] signature = Convert.FromBase64String("hQ4vOFX+pPJNhXxnbMfzAtLjSVeRBBGCOIjlNoIWvzA=");
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
            bool result = SecretKeyAuth.Verify(message, signature, key);
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void SignAndVerifyTest()
        {
            byte[] key = SecretKeyAuth.GenerateKey();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");

            byte[] signature = SecretKeyAuth.Sign(message, key);
            bool verification = SecretKeyAuth.Verify(message, signature, key);
            Assert.IsTrue(verification);
        }
    }
}