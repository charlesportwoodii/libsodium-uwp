using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class PublicKeyBoxTest
    {
        [TestCategory("PublicKeyBox")]
        [TestMethod]
        public void GenerateNonceText()
        {
            Assert.AreEqual(24, PublicKeyBox.GenerateNonce().Length);
        }

        [TestCategory("PublicKeyBox")]
        [TestMethod]
        public void GenerateKeyPairTest()
        {
            var kp = PublicKeyBox.GenerateKeyPair();
            Assert.AreEqual(32, kp.Public.Length);
            Assert.AreEqual(32, kp.Secret.Length);
        }

        [TestCategory("PublicKeyBox")]
        [TestMethod]
        public void GenerateKeyPairFromSeedTest()
        {
            // Generates 32 random bytes as a seed.
            var key = Core.GetRandomBytes(32);
            var kp = PublicKeyBox.GenerateKeyPair(key);
            Assert.AreEqual(32, kp.Public.Length);
            Assert.AreEqual(32, kp.Secret.Length);

            // Check against a generated key from libsodium
            var secret = Convert.FromBase64String("xIsxKqHum01qF1EmiV8WLm2jCiEfcHsXZYYucvOStDE=");
            var pub = Convert.FromBase64String("JnZhWB8n7nDgMKXGy2XwXmvLQP9wY4TU3nUJtwultA8=");
            var kp2 = PublicKeyBox.GenerateKeyPair(secret);
            Assert.AreEqual(32, kp2.Public.Length);
            Assert.AreEqual(32, kp2.Secret.Length);
            Assert.AreEqual(Convert.ToBase64String(pub), Convert.ToBase64String(kp2.Public));
            Assert.AreEqual(Convert.ToBase64String(secret), Convert.ToBase64String(kp2.Secret));
        }

        [TestCategory("PublicKeyBox")]
        [TestMethod]
        public void CreateAndOpenWithOneKeyTest()
        {
            var kp = PublicKeyBox.GenerateKeyPair();
            var nonce = PublicKeyBox.GenerateNonce();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");

            var encrypted = PublicKeyBox.Create(message, nonce, kp.Secret, kp.Public);
            var decrypted = PublicKeyBox.Open(encrypted, nonce, kp.Secret, kp.Public);
            Assert.AreEqual(message.ToString(), decrypted.ToString());
        }

        [TestCategory("PublicKeyBox")]
        [TestMethod]
        public void CreateAndOpenWithKeyExchangeTest()
        {
            var alice = PublicKeyBox.GenerateKeyPair();
            var bob = PublicKeyBox.GenerateKeyPair();
            var nonce = PublicKeyBox.GenerateNonce();
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);

            var encrypted = PublicKeyBox.Create(byteMessage, nonce, alice.Secret, bob.Public);
            var decrypted = PublicKeyBox.Open(encrypted, nonce, bob.Secret, alice.Public);
            Assert.AreEqual(decrypted.ToString(), byteMessage.ToString());

            var newEncrypted = PublicKeyBox.Create(message, nonce, alice.Secret, bob.Public);
            Assert.AreEqual(Convert.ToBase64String(encrypted), Convert.ToBase64String(newEncrypted));
            var newDecrypted = PublicKeyBox.Open(newEncrypted, nonce, bob.Secret, alice.Public);
            Assert.AreEqual(decrypted.ToString(), newDecrypted.ToString());
        }

        [TestCategory("PublicKeyBox")]
        [TestMethod]
        public void OpenWithKeyAndNonce()
        {
            // Key, CipherText, and Nonce generated from libsodium
            var cipherText = Convert.FromBase64String("9Zz8uwvPNqaSzebM4Lf1Gx9RmsaSiww+P0cUogk=");
            var nonce = Convert.FromBase64String("xMD3oIf1lzGK/3X0zFwB0pkcR4ajrb6N");
            var key = Convert.FromBase64String("xIsxKqHum01qF1EmiV8WLm2jCiEfcHsXZYYucvOStDE=");
            var kp = PublicKeyBox.GenerateKeyPair(key);
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);

            var decrypted = PublicKeyBox.Open(cipherText, nonce, kp.Secret, kp.Public);
            Assert.AreEqual(decrypted.ToString(), byteMessage.ToString());
        }
    }
}
