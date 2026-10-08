using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace WebMoney.Cryptography.Tests
{
    //  Signer в режиме v2 (Ed25519). Эталоны - RFC 8032, раздел 7.1;
    //  строка переводится в байты как NFC + UTF-8 без BOM.
    [TestClass]
    public class SignerV2Tests
    {
        private static byte[] FromHex(string hex)
        {
            var result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }

        private static string SignWithSeed(string seedHex, string message)
        {
            using (var signer = new Signer())
            {
                signer.Initialize(FromHex(seedHex));
                return signer.Sign(message);
            }
        }

        [TestMethod]
        public void Rfc8032_Test1_EmptyMessage()
        {
            var signature = SignWithSeed(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "");

            Assert.AreEqual(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                signature);
        }

        [TestMethod]
        public void Rfc8032_Test2_OneByte()
        {
            //  вектор RFC - байт 0x72, это ASCII 'r': UTF-8 даёт тот же байт
            var signature = SignWithSeed(
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "r");

            Assert.AreEqual(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                signature);
        }

        [TestMethod]
        public void Signature_Is128LowercaseHex_AndDeterministic()
        {
            const string seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";

            var first = SignWithSeed(seed, "test");
            var second = SignWithSeed(seed, "test");

            Assert.AreEqual(128, first.Length);
            Assert.AreEqual(first, first.ToLowerInvariant());
            Assert.AreEqual(first, second, "подпись Ed25519 детерминирована");

            using (var signer = new Signer())
            {
                signer.Initialize(FromHex(seed));
                Assert.AreEqual(first, signer.Sign("test", false), "randomEnable в v2 не учитывается");
            }
        }

        [TestMethod]
        public void Nfc_ComposedAndDecomposedCyrillic_GiveSameSignature()
        {
            const string seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";

            //  "й" одной кодовой точкой и "и" + комбинирующий бревис: буквами в исходнике не отличить
            var composed = "стро" + (char)0x0439 + "ка";
            var decomposed = "стро" + (char)0x0438 + (char)0x0306 + "ка";
            Assert.AreNotEqual(composed, decomposed, "ординальное сравнение обязано их различать");

            Assert.AreEqual(SignWithSeed(seed, composed), SignWithSeed(seed, decomposed));
        }

        [TestMethod]
        public void Message_IsUtf8WithoutBom_NotCp1251()
        {
            const string seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
            const string message = "привет";

            var expected = SignRaw(FromHex(seed), new UTF8Encoding(false).GetBytes(message));
            var withBom = SignRaw(FromHex(seed), new UTF8Encoding(true).GetPreamble().Concat(new UTF8Encoding(false).GetBytes(message)));

            var actual = SignWithSeed(seed, message);

            Assert.AreEqual(expected, actual);
            Assert.AreNotEqual(withBom, actual);
        }

        [TestMethod]
        public void Initialize_WrongSeedLength_Throws()
        {
            using (var signer = new Signer())
            {
                Assert.ThrowsException<ArgumentException>(() => signer.Initialize(new byte[31]));
                Assert.ThrowsException<ArgumentException>(() => signer.Initialize(new byte[64]));
                Assert.ThrowsException<ArgumentNullException>(() => signer.Initialize((byte[])null));
            }
        }

        [TestMethod]
        public void Initialize_KeeperKeyAfterSeed_SwitchesBackToRsa()
        {
            const string xmlKey =
                "<RSAKeyValue><Modulus>VR//nsL+80zQAme+udfPanJjZuTJXbVid0Q8QntlnfAedr57TZnFjKSmCWJspJGU7sLs3VP1c0bs1uGw1MvW8G4F</Modulus><D>fbI2CL2ejA+o7a4CbClZGyKwzzfC/qcTsSm/C4hXwFkbvaTpsx0uzF+gj+Cd5qHlDGzum9Jn45AQzr1Y/qoou78A</D></RSAKeyValue>";

            using (var signer = new Signer())
            {
                signer.Initialize(FromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
                Assert.IsTrue(signer.IsV2);
                Assert.AreEqual(128, signer.Sign("test").Length);

                signer.Initialize(xmlKey);
                Assert.IsFalse(signer.IsV2);
                //  эталон RSA из SignerTests.Test1 - путь RSA не задет
                Assert.AreEqual(
                    "ba4fb77e2cb230f3746f5844df4d4bfb8b939c5a39a55cd5c4cdd0c8371cb0c564ca079f96602065aab8b784e1581db5df0a3b5cef19dda9b1827577de18077e02eb",
                    signer.Sign("test", false));
            }
        }

        [TestMethod]
        public void Xml_RoundTrip_SignsLikeSeedBytes()
        {
            const string seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

            var xml = Signer.ToV2XmlString(FromHex(seed));
            Assert.AreEqual(
                "<Ed25519KeyValue><Seed>" + Convert.ToBase64String(FromHex(seed)) + "</Seed></Ed25519KeyValue>",
                xml);

            using (var signer = new Signer())
            {
                signer.Initialize(xml);
                Assert.IsTrue(signer.IsV2);
                //  эталон RFC 8032, тест 1 - тот же, что при инициализации байтами
                Assert.AreEqual(
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                    signer.Sign(""));
            }
        }

        [TestMethod]
        public void Xml_BadSeed_Throws()
        {
            using (var signer = new Signer())
            {
                Assert.ThrowsException<CryptographicException>(() => signer.Initialize(
                    "<Ed25519KeyValue><Seed>" + Convert.ToBase64String(new byte[31]) + "</Seed></Ed25519KeyValue>"));
                Assert.ThrowsException<CryptographicException>(() => signer.Initialize(
                    "<Ed25519KeyValue><Seed></Seed></Ed25519KeyValue>"));
                Assert.ThrowsException<CryptographicException>(() => signer.Initialize(
                    "<Ed25519KeyValue><Seed>not base64!</Seed></Ed25519KeyValue>"));
                Assert.ThrowsException<CryptographicException>(() => signer.Initialize(
                    "<Ed25519KeyValue></Ed25519KeyValue>"));
            }
        }

        [TestMethod]
        public void Xml_SwitchRsaToV2AndBack()
        {
            const string rsaXml =
                "<RSAKeyValue><Modulus>VR//nsL+80zQAme+udfPanJjZuTJXbVid0Q8QntlnfAedr57TZnFjKSmCWJspJGU7sLs3VP1c0bs1uGw1MvW8G4F</Modulus><D>fbI2CL2ejA+o7a4CbClZGyKwzzfC/qcTsSm/C4hXwFkbvaTpsx0uzF+gj+Cd5qHlDGzum9Jn45AQzr1Y/qoou78A</D></RSAKeyValue>";
            var v2Xml = Signer.ToV2XmlString(FromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));

            using (var signer = new Signer())
            {
                signer.Initialize(rsaXml);
                Assert.IsFalse(signer.IsV2);

                signer.Initialize(v2Xml);
                Assert.IsTrue(signer.IsV2);
                Assert.AreEqual(128, signer.Sign("test").Length);

                signer.Initialize(rsaXml);
                Assert.IsFalse(signer.IsV2);
                //  эталон RSA из SignerTests.Test1
                Assert.AreEqual(
                    "ba4fb77e2cb230f3746f5844df4d4bfb8b939c5a39a55cd5c4cdd0c8371cb0c564ca079f96602065aab8b784e1581db5df0a3b5cef19dda9b1827577de18077e02eb",
                    signer.Sign("test", false));
            }
        }

        [TestMethod]
        public void ToV2XmlString_WrongSeedLength_Throws()
        {
            Assert.ThrowsException<ArgumentException>(() => Signer.ToV2XmlString(new byte[31]));
            Assert.ThrowsException<ArgumentNullException>(() => Signer.ToV2XmlString(null));
        }

        [TestMethod]
        public void Sign_WithCarriageReturn_ThrowsInV2Too()
        {
            using (var signer = new Signer())
            {
                signer.Initialize(FromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
                Assert.ThrowsException<ArgumentException>(() => signer.Sign("a\r\nb"));
            }
        }

        [TestMethod]
        public void Sign_AfterDispose_Throws()
        {
            var signer = new Signer();
            signer.Initialize(FromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
            signer.Dispose();

            Assert.ThrowsException<InvalidOperationException>(() => signer.Sign("test"));
        }

        //  прямой Ed25519 по байтам, независимый от Signer: чтобы проверить именно кодировку
        private static string SignRaw(byte[] seed, byte[] message)
        {
            var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            signer.Init(true, new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(seed, 0));
            signer.BlockUpdate(message, 0, message.Length);
            var signature = signer.GenerateSignature();

            var sb = new StringBuilder(signature.Length * 2);
            foreach (var b in signature)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    internal static class ByteArrayExtensions
    {
        public static byte[] Concat(this byte[] first, byte[] second)
        {
            var result = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
            return result;
        }
    }
}
