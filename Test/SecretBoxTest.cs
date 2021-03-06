﻿using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretBoxTest
    {
        [TestCategory("SecretBox")]
        [TestMethod]
        public void SecretBoxGenerateNonceText()
        {
            Assert.AreEqual(24, SecretBox.GenerateNonce().Length);
        }

        [TestCategory("SecretBox")]
        [TestMethod]
        public void SecretBoxGenerateKeyTest()
        {
            Assert.AreEqual(32, SecretBox.GenerateKey().Length);
        }

        [TestCategory("SecretBox")]
        [TestMethod]
        public void SecretBoxCreateTest()
        {
            // Randomly generate key and nonce from a separate libsodium implementation
            var key = "7IygDz/Hy8LC/wqXb6vsrpq7Vyn7mxCoh8nYOn5yVXc=";
            var nonce = "bUBIsnfvIv2Wo95SEkt4DIvBqZLGGBjV";
            String message = "Hello, World!";

            String expectedCipherText = "cZFTGV7SrPeSdX5Q6b30PBEm5Y2uby/W5BSrrfU=";
            byte[] expectedCipherTextBytes = Convert.FromBase64String(expectedCipherText);

            byte[] bitKey = Convert.FromBase64String(key);
            byte[] bitNonce = Convert.FromBase64String(nonce);
            byte[] cipherText = SecretBox.Create(System.Text.Encoding.UTF8.GetBytes(message), bitNonce, bitKey);

            Assert.AreEqual(expectedCipherText, Convert.ToBase64String(cipherText));

            cipherText = SecretBox.Create(message, bitNonce, bitKey);
            Assert.AreEqual(expectedCipherText, Convert.ToBase64String(cipherText));
        }

        [TestCategory("SecretBox")]
        [TestMethod]
        public void SecretBoxOpenTest()
        {
            var key = "7IygDz/Hy8LC/wqXb6vsrpq7Vyn7mxCoh8nYOn5yVXc=";
            var nonce = "bUBIsnfvIv2Wo95SEkt4DIvBqZLGGBjV";
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");

            String cipherText = "cZFTGV7SrPeSdX5Q6b30PBEm5Y2uby/W5BSrrfU=";
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            byte[] bitKey = Convert.FromBase64String(key);
            byte[] bitNonce = Convert.FromBase64String(nonce);
            byte[] plainText = SecretBox.Open(cipherTextBytes, bitNonce, bitKey);

            Assert.AreEqual(message.ToString(), plainText.ToString());
        }

        [TestCategory("SecretBox")]
        [TestMethod]
        public void SecretBoxOpenWithGeneratedDataTest()
        {
            var key = SecretBox.GenerateKey();
            var nonce = SecretBox.GenerateNonce();
            String message = "Hello, World!";

            byte[] plainText = System.Text.Encoding.UTF8.GetBytes(message);
            byte[] cipherText = SecretBox.Create(plainText, nonce, key);
            byte[] decrypted = SecretBox.Open(cipherText, nonce, key);

            Assert.AreEqual(plainText.ToString(), decrypted.ToString());
        }

        [TestCategory("Detached SecretBox")]
        [TestMethod]
        public void DetachedSecretBoxTest()
        {
            var nonce = Sodium.SecretBox.GenerateNonce();
            var key = Sodium.SecretBox.GenerateKey();
            var message = System.Text.Encoding.UTF8.GetBytes("Charles R. Portwood II");
            var actual = Sodium.SecretBox.CreateDetached(message, nonce, key);

            Assert.AreEqual(actual.Mac.Length, 16);
            var clear = Sodium.SecretBox.OpenDetached(actual.Cipher, actual.Mac, nonce, key);

            Assert.AreEqual(Convert.ToBase64String(message), Convert.ToBase64String(clear));

            clear = Sodium.SecretBox.OpenDetached(actual, nonce, key);
            Assert.AreEqual(Convert.ToBase64String(message), Convert.ToBase64String(clear));
        }
    }
}
