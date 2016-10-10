using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SealedPublicKeyBoxTest
    {
        [TestMethod]
        public void CreateAndOpenSealedBoxWithTest()
        {
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
            var keyPair = PublicKeyBox.GenerateKeyPair();

            var encrypted = SealedPublicKeyBox.Create(message, keyPair.Public);
            var decrypted = SealedPublicKeyBox.Open(encrypted, keyPair.Secret, keyPair.Public);
            Assert.AreEqual(message.ToString(), decrypted.ToString());
        }

        [TestMethod]
        public void CreateAndOpenSealedBoxWithKeyPairTest()
        {
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
            var keyPair = PublicKeyBox.GenerateKeyPair();

            var encrypted = SealedPublicKeyBox.Create(message, keyPair.Public);
            var decrypted = SealedPublicKeyBox.Open(encrypted, keyPair);
            Assert.AreEqual(message.ToString(), decrypted.ToString());
        }
    }
}
