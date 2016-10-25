using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class CryptoHashTest
    {
        // sha outputs are the corresponding sha of hashString
        const String hashString = "Charles R. Portwood II";
        const String sha256out = "d6cbe4e3af308a3506c7f3caaa0a0541382d2d7f3d3f8c2a4698e4933d22741a";
        const String sha512out = "48566c83fb3e3b65dbb0e9781d65560aaeadc4f2ac7a521a604c21eec8a5cc06c88a9ba415f4b6b4d6673be3c6d10670485660dcdb362a11ea5f79fb4fe3cf67";

        [TestCategory("CryptoHash")]
        [TestMethod]
        public void Sha256Test()
        {
            var sha256 = CryptoHash.Sha256(System.Text.Encoding.UTF8.GetBytes(hashString));
            string hex = BitConverter.ToString(sha256).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(sha256out, hex);

            sha256 = CryptoHash.Sha256(hashString);
            hex = BitConverter.ToString(sha256).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(sha256out, hex);
        }

        [TestCategory("CryptoHash")]
        [TestMethod]
        public void Sha512Test()
        {
            var sha512 = CryptoHash.Sha512(System.Text.Encoding.UTF8.GetBytes(hashString));
            string hex = BitConverter.ToString(sha512).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(sha512out, hex);

            sha512 = CryptoHash.Sha512(hashString);
            hex = BitConverter.ToString(sha512).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(sha512out, hex);
        }

        [TestCategory("CryptoHash")]
        [TestMethod]
        public void HashTest()
        {
            var hash = CryptoHash.Hash(System.Text.Encoding.UTF8.GetBytes(hashString));
            string hex = BitConverter.ToString(hash).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(sha512out, hex);

            hash = CryptoHash.Hash(hashString);
            hex = BitConverter.ToString(hash).Replace("-", string.Empty).ToLower();
            Assert.AreEqual(sha512out, hex);
        }
    }
}
