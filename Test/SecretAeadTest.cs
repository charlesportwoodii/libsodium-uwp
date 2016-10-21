using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretAeadTest
    {
        [TestCategory("SecretAead::Chacha20-Poly1309")]
        [TestMethod]
        public void GenerateNonceTest()
        {
            Assert.AreEqual(8, SecretAead.GenerateNonce().Length);
        }

        [TestCategory("SecretAead::Chacha20-Poly1309")]
        [TestMethod]
        public void EncryptAndDecryptTest()
        {
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var key = SecretBox.GenerateKey();
            var nonce = SecretAead.GenerateNonce();
            var encrypted = SecretAead.Encrypt(byteMessage, nonce, key);
            var decrypted = SecretAead.Decrypt(encrypted, nonce, key);
            Assert.AreEqual(byteMessage.ToString(), decrypted.ToString());

            var newEncrypted = SecretAead.Encrypt(message, nonce, key);
            Assert.AreEqual(Convert.ToBase64String(encrypted), Convert.ToBase64String(newEncrypted));
            decrypted = SecretAead.Decrypt(newEncrypted, nonce, key);
            Assert.AreEqual(byteMessage.ToString(), decrypted.ToString());
        }

        [TestCategory("SecretAead::Chacha20-Poly1309")]
        [TestMethod]
        public void EncryptAndDecryptWithADTest()
        {
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            byte[] ad = System.Text.Encoding.UTF8.GetBytes("Additional Data");
            var key = SecretBox.GenerateKey();
            var nonce = SecretAead.GenerateNonce();
            var encrypted = SecretAead.Encrypt(byteMessage, nonce, key, ad);
            var decrypted = SecretAead.Decrypt(encrypted, nonce, key, ad);
            Assert.AreEqual(byteMessage.ToString(), decrypted.ToString());

            encrypted = SecretAead.Encrypt(message, nonce, key, ad);
            decrypted = SecretAead.Decrypt(encrypted, nonce, key, ad);
            Assert.AreEqual(byteMessage.ToString(), decrypted.ToString());
        }

        /// <remarks>Binary source from: https://github.com/jedisct1/libsodium/blob/master/test/default/aead_chacha20poly1305.c</remarks>
        [TestCategory("SecretAead::Chacha20-Poly1309")]
        [TestMethod]
        public void AeadWithAdditionalDataTest()
        {
            var key = new byte[]
            {
                0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
                0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
                0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07
            };

            var nonce = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a
            };

            var ad = new byte[]
            {
                0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0
            };

            var m = new byte[]
            {
                0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca
            };

            var encrypted = SecretAead.Encrypt(m, nonce, key, ad);
            var decrypted = SecretAead.Decrypt(encrypted, nonce, key, ad);

            Assert.AreEqual(m.ToString(), decrypted.ToString());
        }

        /// <remarks>Binary source from: https://github.com/jedisct1/libsodium/blob/master/test/default/aead_chacha20poly1305.c</remarks>
        [TestCategory("SecretAead::Chacha20-Poly1309")]
        [TestMethod]
        public void AeadWithoutAdditionalDataTest()
        {
            var key = new byte[]
            {
                0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
                0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
                0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07
            };

            var nonce = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a
            };

            var m = new byte[]
            {
                0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca
            };

            var encrypted = SecretAead.Encrypt(m, nonce, key);
            var decrypted = SecretAead.Decrypt(encrypted, nonce, key);

            Assert.AreEqual(m.ToString(), decrypted.ToString());
        }
    }
}
