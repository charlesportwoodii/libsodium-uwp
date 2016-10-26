using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class ShortHashTest
    {
        [TestCategory("ShortHash")]
        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(16, ShortHash.GenerateKey().Length);
        }

        [TestCategory("ShortHash")]
        [TestMethod]
        public void GenerateHashTest()
        {
            string message = "Hello, World!";
            var key = ShortHash.GenerateKey();
            var hash = ShortHash.Hash(message, key);
            Assert.AreEqual(8, hash.Length);

            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            hash = ShortHash.Hash(byteMessage, key);
            Assert.AreEqual(8, hash.Length);
        }

        [TestCategory("ShortHash")]
        [TestMethod]
        public void CompareHashTest()
        {
            // Test against known values generated from another libsodium implementation
            string message = "Charles R. Portwood II";
            var expected = Convert.FromBase64String("docyE6GyPUA=");
            var key = Convert.FromBase64String("4f7fFH5QJtm/7nqinCcRtA==");
            var hash = ShortHash.Hash(message, key);
            Assert.AreEqual(8, hash.Length);
            Assert.AreEqual(Convert.ToBase64String(expected), Convert.ToBase64String(hash));
        }
    }
}