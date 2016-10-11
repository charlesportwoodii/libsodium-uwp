using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class UtilitiesTest
    {
        [TestMethod]
        public void IncrementTest()
        {
            var nonce = Convert.FromBase64String("djaDJesnKwzeBvqy8BCz9ezVqAVwnpUF");
            var inc = Utilities.Increment(nonce);
            Assert.AreNotEqual(Convert.ToBase64String(nonce), Convert.ToBase64String(inc));
        }

        [TestMethod]
        public void CompareTest()
        {
            var a = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a
            };

            var b = new byte[]
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            };

            var c = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a
            };

            var d = new byte[]
            {
                0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c
            };

            Assert.AreEqual(false, Utilities.Compare(a, b));
            Assert.AreEqual(true, Utilities.Compare(a, c));
            Assert.AreEqual(false, Utilities.Compare(a, d));
            Assert.AreEqual(false, Utilities.Compare(d, b));
        }
    }
}
