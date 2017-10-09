using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretStream
    {
        [TestCategory("SecretStream")]
        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(32, Sodium.SecretStream.GenerateKey().Length);
        }

        [TestCategory("SecretStream")]
        [TestMethod]
        public void GenerateHeaderTest()
        {
            Assert.AreEqual(24, Sodium.SecretStream.GenerateHeader().Length);
        }

        [TestCategory("SecretStream")]
        [TestMethod]
        public void EncryptAndDecryptTest()
        {
            var key = Sodium.SecretStream.GenerateKey();
            var header = Sodium.SecretStream.GenerateHeader();
            var encrypter = new Sodium.SecretStream(key, header, Sodium.SecretStream.MODE_PUSH);
            var decrypter = new Sodium.SecretStream(key, header, Sodium.SecretStream.MODE_PULL);
            
            var message1 = "Hello, World!";
            var message2 = "{ \"json\": \"data\" }";

            var ciphertext1 = encrypter.Push(message1);
            encrypter.Rekey();
            var ciphertext2 = encrypter.Push(message2, Sodium.SecretStream.TAG_FINAL);

            var d1 = decrypter.Pull(ciphertext1);
            decrypter.Rekey();
            var d2 = decrypter.Pull(ciphertext2, Sodium.SecretStream.TAG_FINAL);

            // Verify that the original string and the decrypted string are equivalent
            Assert.AreEqual(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(message1)), Convert.ToBase64String(d1));
            Assert.AreEqual(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(message2)), Convert.ToBase64String(d2));
        }
    }
}
