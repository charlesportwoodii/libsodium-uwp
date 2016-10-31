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
            // Run this test with low memory so it doesn't take forever
            var options = new PasswordHashOptions
            {
                time_cost = 3,
                memory_cost = 1<<8
            };

            string password = "correct horse battery staple";
            var hash = PasswordHash.Hash(password, PasswordHash.Argon2i, options);
            Assert.IsTrue(PasswordHash.Verify(hash, password));
            Assert.IsFalse(PasswordHash.Verify(hash, "the wrong password"));
        }

        [TestCategory("PasswordHash")]
        [TestMethod]
        public void ScryptTest()
        {
            // Run this test with low memory so it doesn't take forever
            var options = new PasswordHashOptions
            {
                time_cost = 1 << 10,
                memory_cost = 1 << 9
            };

            string password = "correct horse battery staple";
            var hash = PasswordHash.Hash(password, PasswordHash.Scrypt, options);
            Assert.IsTrue(PasswordHash.Verify(hash, password));
            Assert.IsFalse(PasswordHash.Verify(hash, "the wrong password"));
        }
    }
}
