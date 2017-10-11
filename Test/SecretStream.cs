using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretStreamTest
    {
        [TestCategory("SecretStream")]
        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(32, SecretStream.GenerateKey().Length);
        }

        [TestCategory("SecretStream")]
        [TestMethod]
        public void GenerateHeaderTest()
        {
            Assert.AreEqual(24, SecretStream.GenerateHeader().Length);
        }

        [TestCategory("SecretStream")]
        [TestMethod]
        public void EncryptAndDecryptTest()
        {
            var key = SecretStream.GenerateKey();
            var header = SecretStream.GenerateHeader();
            var encrypter = new SecretStream(key, header, SecretStream.MODE_PUSH);
            var decrypter = new SecretStream(key, header, SecretStream.MODE_PULL);
            
            var message1 = "Hello, World!";
            var message2 = "{ \"json\": \"data\" }";
            var message3 = "Some more random messaging";

            var ciphertext1 = encrypter.Push(message1);
            encrypter.Rekey();
            var ciphertext2 = encrypter.Push(message2, SecretStream.TAG_PUSH);
            var ciphertext3 = encrypter.Push(message3, SecretStream.TAG_FINAL);

            int tag = -1;
            var d1 = decrypter.Pull(ciphertext1, out tag);
            Assert.AreEqual(tag, SecretStream.TAG_MESSAGE);
            decrypter.Rekey();
            var d2 = decrypter.Pull(ciphertext2, out tag);
            Assert.AreEqual(tag, SecretStream.TAG_PUSH);
            var d3 = decrypter.Pull(ciphertext3, out tag);
            Assert.AreEqual(tag, SecretStream.TAG_FINAL);

            // Verify that the original string and the decrypted string are equivalent
            Assert.AreEqual(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(message1)), Convert.ToBase64String(d1));
            Assert.AreEqual(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(message2)), Convert.ToBase64String(d2));
            Assert.AreEqual(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(message3)), Convert.ToBase64String(d3));
        }
    }
}
