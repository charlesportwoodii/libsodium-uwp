using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class PublicKeyBoxTest
    {
        [TestMethod]
        public void GenerateNonceText()
        {
            Assert.AreEqual(24, PublicKeyBox.GenerateNonce().Length);
        }

        [TestMethod]
        public void GenerateKeyPairTest()
        {
            var kp = PublicKeyBox.GenerateKeyPair();
            Assert.AreEqual(32, kp.Public.Length);
            Assert.AreEqual(32, kp.Secret.Length);
        }

        [TestMethod]
        public void GenerateKeyPairFromSeedTest()
        {
            // Generates 32 random bytes as a seed.
            var key = Core.GetRandomBytes(32);
            var kp = PublicKeyBox.GenerateKeyPair(key);
            Assert.AreEqual(32, kp.Public.Length);
            Assert.AreEqual(32, kp.Secret.Length);

            // Check against a generated seed from libsodium
            var seed = Convert.FromBase64String("slv6S2haNNh4Y3SzDk6VK3wCsfn5p/4MaFHdXjCpMP8=");
            var secret = Convert.FromBase64String("xIsxKqHum01qF1EmiV8WLm2jCiEfcHsXZYYucvOStDE=");
            var pub = Convert.FromBase64String("JnZhWB8n7nDgMKXGy2XwXmvLQP9wY4TU3nUJtwultA8=");
            kp = PublicKeyBox.GenerateKeyPair(key);
            Assert.AreEqual(32, kp.Public.Length);
            Assert.AreEqual(32, kp.Secret.Length);
            Assert.AreEqual(pub.ToString(), kp.Public.ToString());
            Assert.AreEqual(secret.ToString(), kp.Secret.ToString());
        }

        [TestMethod]
        public void CreateAndOpenWithOneKeyTest()
        {
            var kp = PublicKeyBox.GenerateKeyPair();
            var nonce = PublicKeyBox.GenerateNonce();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");

            var encrypted = PublicKeyBox.Create(message, nonce, kp.Secret, kp.Public);
            var decrypted = PublicKeyBox.Open(encrypted, nonce, kp.Secret, kp.Public);
            Assert.AreEqual(decrypted.ToString(), message.ToString());
        }

        [TestMethod]
        public void CreateAndOpenWithKeyExchangeTest()
        {
            var alice = PublicKeyBox.GenerateKeyPair();
            var bob = PublicKeyBox.GenerateKeyPair();
            var nonce = PublicKeyBox.GenerateNonce();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");

            var encrypted = PublicKeyBox.Create(message, nonce, alice.Secret, bob.Public);
            var decrypted = PublicKeyBox.Open(encrypted, nonce, bob.Secret, alice.Public);
            Assert.AreEqual(decrypted.ToString(), message.ToString());
        }
    }
}
