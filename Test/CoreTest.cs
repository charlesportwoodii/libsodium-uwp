using System;
using Sodium;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Test
{
    [TestClass]
    public class CoreTest
    {
        [TestCategory("Core")]
        [TestMethod]
        public void SodiumVersionStringTest()
        {
            const string EXPECTED = "1.0.11";
            var actual = Core.SodiumVersionString();
            Assert.AreEqual(EXPECTED, actual);
            
            actual = Core.SodiumVersionString();
            Assert.AreNotEqual("1.0.10", actual);
        }

        [TestCategory("Core")]
        [TestMethod]
        public void GetRandomBytesTest()
        {
            int[] numbers = new int[] {
                2,
                4,
                8,
                16,
                24,
                32,
                64,
                128,
                256
            };
            foreach (int i in numbers)
            {
                byte[] bytes = Core.GetRandomBytes(i);
                Assert.IsTrue(bytes.Length == i);
            }
        }

        [TestCategory("Core")]
        [TestMethod]
        public void GetRandomNumberTest()
        {
            int[] numbers = new int[] {
                5,
                8,
                10,
                16,
                24,
                32,
                64,
                100,
                10000,
                50000
            };

            foreach (int i in numbers)
            {
                int n = Core.GetRandomNumber(i);
                Assert.IsTrue(n <= i);
            }
        }
    }
}
