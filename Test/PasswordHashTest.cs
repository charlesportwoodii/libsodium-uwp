using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class PasswordHashTest
    {
        [TestCategory("PasswordHash")]
        [TestMethod]
        public void Argon2iTest()
        {
            var options = PasswordHash.CreateOptions(1 << 8, 3);

            string password = "correct horse battery staple";
            var hash = PasswordHash.Hash(password, PasswordHash.Argon2i, options);
            Assert.IsTrue(PasswordHash.Verify(hash, password));
            Assert.IsFalse(PasswordHash.Verify(hash, "the wrong password"));
        }

        [TestCategory("PasswordHash")]
        [TestMethod]
        public void Argon2idTest()
        {
            var options = PasswordHash.CreateOptions(1 << 8, 3);

            string password = "correct horse battery staple";
            var hash = PasswordHash.Hash(password, PasswordHash.Argon2id, options);
            Assert.IsTrue(PasswordHash.Verify(hash, password));
            Assert.IsFalse(PasswordHash.Verify(hash, "the wrong password"));
        }

        [TestCategory("PasswordHash")]
        [TestMethod]
        public void NeedsRehashTest()
        {
            var options = PasswordHash.CreateOptions(1 << 8, 3);

            string password = "correct horse battery staple";
            var hash = PasswordHash.Hash(password, PasswordHash.Argon2id, options);
            Assert.IsFalse(PasswordHash.NeedsRehash(hash, options));

            var newOptions = PasswordHash.CreateOptions(1 << 8, 4);
            Assert.IsTrue(PasswordHash.NeedsRehash(hash, newOptions));
        }

        [TestCategory("PasswordHash")]
        [TestMethod]
        public void ScryptTest()
        {
            var options = PasswordHash.CreateOptions(1 << 8, 3);

            string password = "correct horse battery staple";
            var hash = PasswordHash.Hash(password, PasswordHash.Scrypt, options);
            Assert.IsTrue(PasswordHash.Verify(hash, password));
            Assert.IsFalse(PasswordHash.Verify(hash, "the wrong password"));
        }
    }
}
