using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class GenericHashTest
    {
        [TestCategory("GenericHash")]
        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(64, GenericHash.GenerateKey().Length);
        }

        [TestCategory("GenericHash")]
        [TestMethod]
        public void HashTest()
        {
            var message = "Charles R. Portwood II";
            var byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var expected = "1z44ap/6a2sdvg3axIXrIieqsoMwNX6zquW2Q4xqu+s=";

            var result = GenericHash.Hash(message);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(32, result.Length);

            result = GenericHash.Hash(byteMessage);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(32, result.Length);
        }

        // Expected value and key are derived from libsodium-php
        [TestCategory("GenericHash")]
        [TestMethod]
        public void HashWithKeyTest()
        {
            var message = "Charles R. Portwood II";
            var key = Convert.FromBase64String("vq3zTrdu4ig/MsmLOaSOcF/1owV6W/XEKwmtVlO7Mxs=");
            var byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var expected = "ttTxoTNX5L9UmL5p5DqPlUGciDSpWYgeFQ+zc9xYJHM=";

            var result = GenericHash.Hash(message, key);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(32, result.Length);

            result = GenericHash.Hash(byteMessage, key);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(32, result.Length);
        }

        // Expected value and key are derived from libsodium-php
        [TestCategory("GenericHash")]
        [TestMethod]
        public void HashWithKeyAndBytesTest()
        {
            var message = "Charles R. Portwood II";
            var key = Convert.FromBase64String("vq3zTrdu4ig/MsmLOaSOcF/1owV6W/XEKwmtVlO7Mxs=");
            var byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var expected = "VSHhHbAOM7+izLnWLUXA3TcwSwipIQfMs4uFILihM3LpqP64WOoyeqP75vVkM/jQIWhgreFBypDDn8GnPobSxg==";
            var bytes = 64;

            var result = GenericHash.Hash(message, key, bytes);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(64, result.Length);

            result = GenericHash.Hash(byteMessage, key, bytes);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(64, result.Length);
        }

        // Expected value and key are derived from libsodium-php
        [TestCategory("GenericHash")]
        [TestMethod]
        public void HashWithNullKeyAndLengthTest()
        {
            var message = "Charles R. Portwood II";
            var byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var expected = "UIm6VdkkXtsbkaqEpogES9mMaKO5fT3ROaUQ8IgMItd8Q6bi++t/66UqQKcxkSL0kVUoxj5OlhlOv/AisgyHyg==";
            var bytes = 64;

            var result = GenericHash.Hash(message, null, bytes);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(64, result.Length);

            result = GenericHash.Hash(byteMessage, null, bytes);
            Assert.AreEqual(expected, Convert.ToBase64String(result));
            Assert.AreEqual(64, result.Length);
        }
    }
}
