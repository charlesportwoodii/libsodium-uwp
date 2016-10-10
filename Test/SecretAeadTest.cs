using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class SecretAeadTest
    {
        [TestMethod]
        public void GenerateNonceText()
        {
            Assert.AreEqual(8, SecretAead.GenerateNonce().Length);
        }
    }
}
