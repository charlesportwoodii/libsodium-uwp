using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class OneTimeAuthTest
    {
        [TestCategory("OneTimeAuth")]
        [TestMethod]
        public void GenerateKeyTest()
        {
            Assert.AreEqual(32, OneTimeAuth.GenerateKey().Length);
        }

        [TestCategory("OneTimeAuth")]
        [TestMethod]
        public void SignAndVerifyTest()
        {
            string message = "Hello, World!";
            byte[] byteMessage = System.Text.Encoding.UTF8.GetBytes(message);
            var key = OneTimeAuth.GenerateKey();

            var sig1 = OneTimeAuth.Sign(message, key);
            var sig2 = OneTimeAuth.Sign(byteMessage, key);
            
            // Verify the outputs of the overload are equal
            Assert.AreEqual(Convert.ToBase64String(sig1), Convert.ToBase64String(sig2));

            var result = false;

            result = OneTimeAuth.Verify(message, sig1, key);
            Assert.IsTrue(result);
            result = OneTimeAuth.Verify(message, sig2, key);
            Assert.IsTrue(result);
            result = OneTimeAuth.Verify(byteMessage, sig1, key);
            Assert.IsTrue(result);
            result = OneTimeAuth.Verify(byteMessage, sig2, key);
            Assert.IsTrue(result);

            result = OneTimeAuth.Verify("test", sig1, key);
            Assert.IsFalse(result);
        }
    }
}
