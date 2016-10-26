using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class StreamEncryptionTest
    {
        [TestCategory("StreamEncryption")]
        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(32, StreamEncryption.GenerateKey().Length);
        }

        [TestCategory("StreamEncryption")]
        [TestMethod]
        public void GenerateNonceTest()
        {
            Assert.AreEqual(24, StreamEncryption.GenerateNonce().Length);
        }

        [TestCategory("StreamEncryption :: XSalsa20")]
        [TestMethod]
        public void GenerateNonceXSalsa20Test()
        {
            Assert.AreEqual(24, StreamEncryption.GenerateNonceXSalsa20().Length);
        }

        [TestCategory("StreamEncryption :: ChaCha20")]
        [TestMethod]
        public void GenerateNonceChaCha20Test()
        {
            Assert.AreEqual(8, StreamEncryption.GenerateNonceChaCha20().Length);
        }


        [TestCategory("StreamEncryption :: Salsa20")]
        [TestMethod]
        public void GenerateNonceSalsa20Test()
        {
            Assert.AreEqual(8, StreamEncryption.GenerateNonceSalsa20().Length);
        }


        [TestCategory("StreamEncryption :: XSalsa20")]
        [TestMethod]
        public void XSalsa20Test()
        {
            var key = StreamEncryption.GenerateKey();
            var nonce = StreamEncryption.GenerateNonce();
            string message = "Hello, World!";

            var cipherText = StreamEncryption.Encrypt(message, nonce, key);
            var decrypted = StreamEncryption.Decrypt(cipherText, nonce, key);
            Assert.AreEqual(message, System.Text.Encoding.UTF8.GetString(decrypted));

            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            cipherText = StreamEncryption.Encrypt(byteMessage, nonce, key);
            decrypted = StreamEncryption.Decrypt(cipherText, nonce, key);
            Assert.AreEqual(Convert.ToBase64String(byteMessage), Convert.ToBase64String(decrypted));

            cipherText = StreamEncryption.EncryptXSalsa20(message, nonce, key);
            decrypted = StreamEncryption.DecryptXSalsa20(cipherText, nonce, key);
            Assert.AreEqual(message, System.Text.Encoding.UTF8.GetString(decrypted));

            byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            cipherText = StreamEncryption.EncryptXSalsa20(byteMessage, nonce, key);
            decrypted = StreamEncryption.DecryptXSalsa20(cipherText, nonce, key);
            Assert.AreEqual(Convert.ToBase64String(byteMessage), Convert.ToBase64String(decrypted));
        }


        [TestCategory("StreamEncryption :: Salsa20")]
        [TestMethod]
        public void Salsa20Test()
        {
            var key = StreamEncryption.GenerateKey();
            var nonce = StreamEncryption.GenerateNonceSalsa20();
            string message = "Hello, World!";

            var cipherText = StreamEncryption.EncryptSalsa20(message, nonce, key);
            var decrypted = StreamEncryption.DecryptSalsa20(cipherText, nonce, key);
            Assert.AreEqual(message, System.Text.Encoding.UTF8.GetString(decrypted));

            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            cipherText = StreamEncryption.EncryptSalsa20(byteMessage, nonce, key);
            decrypted = StreamEncryption.EncryptSalsa20(cipherText, nonce, key);
            Assert.AreEqual(Convert.ToBase64String(byteMessage), Convert.ToBase64String(decrypted));
        }


        [TestCategory("StreamEncryption :: ChaCha20")]
        [TestMethod]
        public void ChaCha20Test()
        {
            var key = StreamEncryption.GenerateKey();
            var nonce = StreamEncryption.GenerateNonceChaCha20();
            string message = "Hello, World!";

            var cipherText = StreamEncryption.EncryptChaCha20(message, nonce, key);
            var decrypted = StreamEncryption.DecryptChaCha20(cipherText, nonce, key);
            Assert.AreEqual(message, System.Text.Encoding.UTF8.GetString(decrypted));

            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            cipherText = StreamEncryption.EncryptChaCha20(byteMessage, nonce, key);
            decrypted = StreamEncryption.DecryptChaCha20(cipherText, nonce, key);
            Assert.AreEqual(Convert.ToBase64String(byteMessage), Convert.ToBase64String(decrypted));
        }


        [TestCategory("StreamEncryption :: XSalsa20")]
        [TestMethod]
        public void XSalsa20SodiumTest()
        {
            var firstkey = new byte[]
            {
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
                0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
                0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
            };

            var nonce = new byte[]
            {
                0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
                0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
                0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
            };

            var m = new byte[]
            {
                0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
                0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
                0,    0,    0,    0,    0,    0,    0,    0,    0xbe, 0x07, 0x5f, 0xc5,
                0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
                0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66, 0x84, 0x9b,
                0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
                0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29, 0x6c, 0xdc, 0x3c, 0x01,
                0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
                0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f,
                0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
                0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde, 0x04, 0x89, 0x77, 0xeb,
                0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
                0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37,
                0x76, 0x38, 0x48, 0x64, 0x5e, 0x07, 0x05
            };

            var actual = StreamEncryption.Encrypt(m, nonce, firstkey);
            Assert.AreEqual(163, actual.Length);
        }
    }
}
