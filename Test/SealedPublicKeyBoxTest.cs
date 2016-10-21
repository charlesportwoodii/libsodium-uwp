using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SealedPublicKeyBoxTest
    {
        [TestCategory("SealedPublicKeyBox")]
        [TestMethod]
        public void CreateAndOpenSealedBoxTest()
        {
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var keyPair = PublicKeyBox.GenerateKeyPair();

            var encrypted = SealedPublicKeyBox.Create(byteMessage, keyPair.Public);
            var decrypted = SealedPublicKeyBox.Open(encrypted, keyPair.Secret, keyPair.Public);
            Assert.AreEqual(byteMessage.ToString(), decrypted.ToString());

            var newEncrypted = SealedPublicKeyBox.Create(message, keyPair.Public);
            var newDecrypted = SealedPublicKeyBox.Open(newEncrypted, keyPair.Secret, keyPair.Public);
            Assert.AreEqual(decrypted.ToString(), newDecrypted.ToString());
        }

        [TestCategory("SealedPublicKeyBox")]
        [TestMethod]
        public void CreateAndOpenSealedBoxWithKeyPairTest()
        {
            String message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var keyPair = PublicKeyBox.GenerateKeyPair();

            var encrypted = SealedPublicKeyBox.Create(byteMessage, keyPair.Public);
            var decrypted = SealedPublicKeyBox.Open(encrypted, keyPair);
            Assert.AreEqual(byteMessage.ToString(), decrypted.ToString());

            var newEncrypted = SealedPublicKeyBox.Create(message, keyPair.Public);
            var newDecrypted = SealedPublicKeyBox.Open(newEncrypted, keyPair);
            Assert.AreEqual(decrypted.ToString(), newDecrypted.ToString());
        }
    }
}
