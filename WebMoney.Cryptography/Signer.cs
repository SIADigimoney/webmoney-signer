using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using WebMoney.Cryptography.Internal;

namespace WebMoney.Cryptography
{
#if DEBUG
#else
    [System.Diagnostics.DebuggerNonUserCode]
#endif
    [ComVisible(true)]
    public class Signer : ISigner, IDisposable
    {
        private const int ByteSize = 8;
        private const int Int32Size = 32;
        private const int Int16Size = 16;
        private const int HashSize = 128;

        private static readonly byte[] Header = { 0x38, 0 };
        private static readonly byte[] Tail = { 1, 0 };

        /// <summary>Длина приватного ключа подписи v2 (сида Ed25519) в байтах.</summary>
        public const int V2SeedSize = 32;

        //  XML-форма ключа v2 по образцу RSAKeyValue: сид Ed25519 в Base64.
        //  Initialize(string) различает схемы по имени корневого элемента.
        private const string V2KeyXmlElement = "Ed25519KeyValue";
        private const string V2KeyXmlTemplate = "<Ed25519KeyValue><Seed>{0}</Seed></Ed25519KeyValue>";

#if NETFRAMEWORK
        //  В .NET Framework кодовые страницы встроены — провайдер и пакет не нужны.
        private static readonly Encoding MessageEncoding = Encoding.GetEncoding(1251);
#else
        private static readonly Encoding MessageEncoding = CodePagesEncodingProvider.Instance.GetEncoding(1251);
#endif

        //  v2: строка приводится к NFC и кодируется UTF-8 без BOM.
        //  RSA-путь остаётся на cp1251, это часть протокола.
        private static readonly Encoding V2MessageEncoding = new UTF8Encoding(false);

        //  Режим подписи задаёт тип ключа, переданного в Initialize: KeeperKey - RSA,
        //  32 байта сида - Ed25519 (v2). По длине байтов не различаем:
        //  32-байтный модуль формально проходит MinimumKeySize и ошибка была бы молчаливой.
        private KeeperKey _key;
        private byte[] _v2Seed;

        private bool _isDisposed;

        /// <summary>Ключ в XML: RSAKeyValue - RSA, Ed25519KeyValue - v2.</summary>
        public void Initialize(string value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            if (string.IsNullOrEmpty(value))
                throw new ArgumentOutOfRangeException(nameof(value));

            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(value);

            var topElement = xmlDocument.DocumentElement;

            if (null != topElement && V2KeyXmlElement == topElement.Name)
            {
                var seedNode = topElement.SelectSingleNode("Seed");

                if (string.IsNullOrEmpty(seedNode?.InnerText))
                    throw new CryptographicException("Input string does not contain a valid encoding of the 'Ed25519' 'Seed' parameter.");

                byte[] seed;

                try
                {
                    seed = Convert.FromBase64String(seedNode.InnerText);
                }
                catch (FormatException)
                {
                    throw new CryptographicException("Input string does not contain a valid encoding of the 'Ed25519' 'Seed' parameter.");
                }

                try
                {
                    if (V2SeedSize != seed.Length)
                        throw new CryptographicException(string.Format(CultureInfo.InvariantCulture,
                            "Invalid key length. The Ed25519 seed must be exactly {0} bytes long.", V2SeedSize));

                    Initialize(seed);
                }
                finally
                {
                    Array.Clear(seed, 0, seed.Length);
                }

                return;
            }

            var keeperKey = new KeeperKey(value);
            Initialize(keeperKey);
        }

        /// <summary>XML-форма ключа v2 для Initialize(string): сид Ed25519 (32 байта) в Base64.</summary>
        public static string ToV2XmlString(byte[] ed25519Seed)
        {
            if (null == ed25519Seed)
                throw new ArgumentNullException(nameof(ed25519Seed));

            if (V2SeedSize != ed25519Seed.Length)
                throw new ArgumentException(
                    string.Format(CultureInfo.InvariantCulture, "Ed25519 seed must be exactly {0} bytes long.", V2SeedSize),
                    nameof(ed25519Seed));

            return string.Format(CultureInfo.InvariantCulture, V2KeyXmlTemplate, Convert.ToBase64String(ed25519Seed));
        }

        [ComVisible(false)]
        public void Initialize(KeeperKey keeperKey)
        {
            if (null == keeperKey)
                throw new ArgumentNullException(nameof(keeperKey));

            ClearV2Seed();
            _key = keeperKey;
        }

        /// <summary>Ключ v2: приватный ключ подписи Ed25519 (сид, 32 байта). Массив копируется.</summary>
        [ComVisible(false)]
        public void Initialize(byte[] ed25519Seed)
        {
            if (null == ed25519Seed)
                throw new ArgumentNullException(nameof(ed25519Seed));

            if (V2SeedSize != ed25519Seed.Length)
                throw new ArgumentException(
                    string.Format(CultureInfo.InvariantCulture, "Ed25519 seed must be exactly {0} bytes long.", V2SeedSize),
                    nameof(ed25519Seed));

            ClearV2Seed();
            _v2Seed = (byte[])ed25519Seed.Clone();
            _key = null;
        }

        /// <summary>true, если загружен ключ v2 (Ed25519); false - RSA или не инициализирован.</summary>
        public bool IsV2 => null != _v2Seed;

        public string Sign(string value)
        {
            return Sign(value, true);
        }

        /// <summary>Подпись строки. RSA: 132 hex, с случайным заполнением при randomEnable.
        /// v2: 128 hex, детерминирована, randomEnable не учитывается.</summary>
        [ComVisible(false)]
        public string Sign(string value, bool randomEnable)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            if (value.IndexOf('\r') >= 0)
                throw new ArgumentException("Message cannot contain of the following character: '\r'.");

            if (null != _v2Seed)
                return SignV2(value);

            if (null == _key)
                throw new InvalidOperationException("Signer must be initialized before it can be used.");

            var hash = ComputeHash(value, 0, value.Length);
            var random = new byte[_key.KeySize / ByteSize - Header.Length - HashSize / ByteSize - Tail.Length];

            if (randomEnable)
            {
                var rng = new RNGCryptoServiceProvider();
                rng.GetBytes(random);
            }

            var blob = new uint[(_key.KeySize / ByteSize + Int32Size / ByteSize - 1) / (Int32Size / ByteSize)];

            Buffer.BlockCopy(Header, 0, blob, 0, Header.Length);
            Buffer.BlockCopy(hash, 0, blob, Header.Length, HashSize / ByteSize);
            Buffer.BlockCopy(random, 0, blob, Header.Length + HashSize / ByteSize, random.Length);
            Buffer.BlockCopy(Tail, 0, blob, Header.Length + HashSize / ByteSize + random.Length, Tail.Length);

            var signature =
                new BigInteger(blob).PerformMontgomeryExponentiation(new BigInteger(_key.D),
                    new BigInteger(_key.Modulus)).ToUInt16Array();

            var stringBuilder = new StringBuilder();

            var keySize = _key.KeySize > KeeperKey.StandardKeySize ? _key.KeySize : KeeperKey.StandardKeySize;

            for (int pos = 0; pos < keySize / Int16Size; pos++)
            {
                stringBuilder.Append(signature.Length > pos
                                         ? string.Format(CultureInfo.InvariantCulture, "{0:x4}", signature[pos])
                                         : string.Format(CultureInfo.InvariantCulture, "{0:x4}", 0));
            }

            return stringBuilder.ToString();
        }

        private string SignV2(string value)
        {
            var message = V2MessageEncoding.GetBytes(value.Normalize(NormalizationForm.FormC));

            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(_v2Seed, 0));
            signer.BlockUpdate(message, 0, message.Length);
            var signature = signer.GenerateSignature();

            //  hex побайтово, в порядке RFC 8032 - не пословно, как у RSA
            var stringBuilder = new StringBuilder(signature.Length * 2);
            foreach (var b in signature)
                stringBuilder.Append(b.ToString("x2", CultureInfo.InvariantCulture));

            return stringBuilder.ToString();
        }

        private void ClearV2Seed()
        {
            if (null == _v2Seed)
                return;

            Array.Clear(_v2Seed, 0, _v2Seed.Length);
            _v2Seed = null;
        }

        private byte[] ComputeHash(string value, int offset, int count)
        {
            byte[] hash;

            using (MD4 md4 = new MD4Managed())
            {
                md4.Initialize();
                hash = md4.ComputeHash(MessageEncoding.GetBytes(value), offset, count);
            }

            return hash;
        }
        
        #region IDisposable Members

        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed)
                return;
            
            if (disposing)
            {
                if (null != _key)
                {
                    _key.Dispose();
                    _key = null;
                }

                ClearV2Seed();
            }

            _isDisposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}