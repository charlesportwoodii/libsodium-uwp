using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

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

        [TestCategory("GenericHash")]
        [TestMethod]
        public void GenericHashProviderTest()
        {
            var provider = GenericHashAlgorithmProvider.OpenAlgorithm(GenericHashAlgorithmNames.Blake2);
            var hash = provider.CreateHash();
            
            IBuffer data = CryptographicBuffer.ConvertStringToBinary("Hello, World!", BinaryStringEncoding.Utf8);
            hash.Append(data);

            // Expected value is calculated from libsodium-php
            var expected = "URvIHd4RGAg4xWLIK7NfMiP0YGHr3kqVXCez9InPHgM=";
            var output = hash.GetValueAndReset();
            Assert.AreEqual(32, output.Length);
            Assert.AreEqual(expected, Convert.ToBase64String(output));
        }

        [TestCategory("GenericHash")]
        [TestMethod]
        public void GenericHashProviderWithKeyTest()
        {
            var provider = GenericHashAlgorithmProvider.OpenAlgorithm(GenericHashAlgorithmNames.Blake2);
            var key = Convert.FromBase64String("vq3zTrdu4ig/MsmLOaSOcF/1owV6W/XEKwmtVlO7Mxs=");
            var hash = provider.CreateHash(key);

            IBuffer data = CryptographicBuffer.ConvertStringToBinary("Hello, World!", BinaryStringEncoding.Utf8);
            hash.Append(data);

            // Expected value is calculated from libsodium-php
            var expected = "bG8y2lpT7rIRWnhK7V8VNkBdQxweRpnvfzQa7yyZeTQ=";
            var output = hash.GetValueAndReset();
            Assert.AreEqual(32, output.Length);
            Assert.AreEqual(expected, Convert.ToBase64String(output));
        }

        [TestCategory("GenericHash")]
        [TestMethod]
        public void GenericHashProviderWithKeyAndBytesTest()
        {
            var provider = GenericHashAlgorithmProvider.OpenAlgorithm(GenericHashAlgorithmNames.Blake2);
            var key = Convert.FromBase64String("vq3zTrdu4ig/MsmLOaSOcF/1owV6W/XEKwmtVlO7Mxs=");
            var hash = provider.CreateHash(key, 64);

            IBuffer data = CryptographicBuffer.ConvertStringToBinary("Hello, World!", BinaryStringEncoding.Utf8);
            hash.Append(data);

            // Expected value is calculated from libsodium-php
            var expected = "iTtxGNvLdiUsd8ceFJSzWtEU4kyegcFvTBlJ4kVc7DxrdenYO6vBy+hZXGbAm2YPSb+3qDc9+SX1y78lCU1QhQ==";
            var output = hash.GetValueAndReset();
            Assert.AreEqual(64, output.Length);
            Assert.AreEqual(expected, Convert.ToBase64String(output));
        }

        [TestCategory("GenericHash")]
        [TestMethod]
        public void GenericHashProviderWithNullKeyAndBytesTest()
        {
            var provider = GenericHashAlgorithmProvider.OpenAlgorithm(GenericHashAlgorithmNames.Blake2);
            var hash = provider.CreateHash(null, 64);

            IBuffer data = CryptographicBuffer.ConvertStringToBinary("Hello, World!", BinaryStringEncoding.Utf8);
            hash.Append(data);

            // Expected value is calculated from libsodium-php
            var expected = "ff24iK9x6uDmprdR6ONBPXZ+9PpSp5k9qp7wl/eqPZSRmcETyqN8lPgM87IvfZ1uT13vT/kngwz/5IV8NL49iQ==";
            var output = hash.GetValueAndReset();
            Assert.AreEqual(64, output.Length);
            Assert.AreEqual(expected, Convert.ToBase64String(output));
        }

        [TestCategory("GenericHash")]
        [TestMethod]
        public void IterativeGenericHashProviderWithNullKeyAndBytesTest()
        {
            var provider = GenericHashAlgorithmProvider.OpenAlgorithm(GenericHashAlgorithmNames.Blake2);
            var hash = provider.CreateHash(null, 64);

            IBuffer data = CryptographicBuffer.ConvertStringToBinary("Hello, World!", BinaryStringEncoding.Utf8);
            hash.Append(data);

            data = CryptographicBuffer.ConvertStringToBinary("Hello, World!", BinaryStringEncoding.Utf8);
            hash.Append(data);

            // Expected value is calculated from libsodium-php
            var expected = "aFml74dODBhwrt9rpIzEXeZRf35k5aA/XJpOOOq4yegxP8CAU9WFFlcJM5Cw3PcPLYFZQOPJI192Ma6b3olrKg==";
            var output = hash.GetValueAndReset();
            Assert.AreEqual(64, output.Length);
            Assert.AreEqual(expected, Convert.ToBase64String(output));
        }
    }
}
