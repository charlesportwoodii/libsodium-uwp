using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretBoxTest
    {
        [TestMethod]
        public void GenerateNonceText()
        {
            Assert.AreEqual(24, SecretBox.GenerateNonce().Length);
        }

        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(32, SecretBox.GenerateKey().Length);
        }

        [TestMethod]
        public void CreateTest()
        {
            // Randomly generate key and nonce from a separate libsodium implementation
            var key = "7IygDz/Hy8LC/wqXb6vsrpq7Vyn7mxCoh8nYOn5yVXc=";
            var nonce = "bUBIsnfvIv2Wo95SEkt4DIvBqZLGGBjV";
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");

            String expectedCipherText = "cZFTGV7SrPeSdX5Q6b30PBEm5Y2uby/W5BSrrfU=";
            byte[] expectedCipherTextBytes = Convert.FromBase64String(expectedCipherText);

            byte[] bitKey = Convert.FromBase64String(key);
            byte[] bitNonce = Convert.FromBase64String(nonce);
            byte[] cipherText = SecretBox.Create(message, bitNonce, bitKey);

            Assert.AreEqual(expectedCipherText, Convert.ToBase64String(cipherText));
        }

        [TestMethod]
        public void OpenTest()
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

        [TestMethod]
        public void OpenWithGeneratedDataTest()
        {
            var key = SecretBox.GenerateKey();
            var nonce = SecretBox.GenerateNonce();
            String message = "Hello, World!";

            byte[] plainText = System.Text.Encoding.UTF8.GetBytes(message);
            byte[] cipherText = SecretBox.Create(plainText, nonce, key);
            byte[] decrypted = SecretBox.Open(cipherText, nonce, key);

            Assert.AreEqual(plainText.ToString(), decrypted.ToString());

        }
    }
}
