//  Чтение файла ключей v2 (.kwm нового формата) на BouncyCastle.
//  Только чтение: утилите нужен сид подписи, запись файла - дело кипера.
//
//  Раскладка (136 байт):
//    0   2   wReserved1 = 0x0081
//    2   2   wSignFlag, в v2 всегда 0
//    4   16  соль Argon2id
//    20  4   dwLenBuf = 112
//    24  4   dwReserv = версия формата (2)
//    28  24  nonce XChaCha20-Poly1305
//    52  68  шифртекст: длина(2) + ключ подписи(32) + длина(2) + ключ обмена(32)
//    120 16  тег Poly1305
//
//  Ключ шифрования - Argon2id от пароля и соли (параметры libsodium
//  INTERACTIVE: 2 прохода, 64 МБ, параллелизм 1, 32 байта).
//  Additional data - первые 52 байта файла плюс WMID в ASCII: подмена
//  заголовка или чужой WMID валят проверку тега.

using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace WebMoney.KeyExtractor.Utils
{
    internal sealed class V2KeyFile
    {
        public const int FileSize = 136;
        public const int KeySize = 32;
        public const int Version = 2;

        private const int SaltOffset = 4;
        private const int SaltSize = 16;
        private const int LenBufOffset = 20;
        private const int VersionOffset = 24;
        private const int NonceOffset = 28;
        private const int NonceSize = 24;
        private const int CipherOffset = 52;
        private const int PlainSize = 68;
        private const int TagSize = 16;
        private const int AdSize = 52;
        private const int BodySize = 112;

        //  libsodium: crypto_pwhash_OPSLIMIT_INTERACTIVE / MEMLIMIT_INTERACTIVE
        private const int Argon2Iterations = 2;
        private const int Argon2MemoryKb = 65536;
        private const int Argon2Parallelism = 1;

        public byte[] SignSeed { get; private set; }
        public byte[] ExchangeKey { get; private set; }

        public static int ReadVersion(byte[] file)
        {
            //  версия читается без пароля: поле не шифруется
            if (null == file || file.Length < VersionOffset + 4)
                return 0;
            return BitConverter.ToInt32(file, VersionOffset);
        }

        public static V2KeyFile Load(byte[] file, string wmid, string password)
        {
            if (null == file)
                throw new ArgumentNullException(nameof(file));
            if (file.Length < FileSize)
                throw new ArgumentException("Файл короче 136 байт - это не ключ v2.", nameof(file));
            if (BodySize != BitConverter.ToInt32(file, LenBufOffset) || Version != ReadVersion(file))
                throw new ArgumentException("Заголовок не соответствует формату v2.", nameof(file));

            var salt = new byte[SaltSize];
            Buffer.BlockCopy(file, SaltOffset, salt, 0, SaltSize);

            var nonce = new byte[NonceSize];
            Buffer.BlockCopy(file, NonceOffset, nonce, 0, NonceSize);

            var fileKey = DeriveFileKey(password, salt);

            //  ad = открытый заголовок + WMID
            var wmidBytes = System.Text.Encoding.ASCII.GetBytes(wmid);
            var ad = new byte[AdSize + wmidBytes.Length];
            Buffer.BlockCopy(file, 0, ad, 0, AdSize);
            Buffer.BlockCopy(wmidBytes, 0, ad, AdSize, wmidBytes.Length);

            var cipher = new byte[PlainSize + TagSize];
            Buffer.BlockCopy(file, CipherOffset, cipher, 0, cipher.Length);

            var plain = XChaCha20Poly1305Decrypt(fileKey, nonce, ad, cipher);
            Array.Clear(fileKey, 0, fileKey.Length);

            if (KeySize != BitConverter.ToUInt16(plain, 0) ||
                KeySize != BitConverter.ToUInt16(plain, 2 + KeySize))
                throw new CryptoException("Тело файла разобрано, но длины ключей не сходятся.");

            var result = new V2KeyFile
            {
                SignSeed = new byte[KeySize],
                ExchangeKey = new byte[KeySize]
            };

            Buffer.BlockCopy(plain, 2, result.SignSeed, 0, KeySize);
            Buffer.BlockCopy(plain, 4 + KeySize, result.ExchangeKey, 0, KeySize);
            Array.Clear(plain, 0, plain.Length);

            return result;
        }

        private static byte[] DeriveFileKey(string password, byte[] salt)
        {
            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithIterations(Argon2Iterations)
                .WithMemoryAsKB(Argon2MemoryKb)
                .WithParallelism(Argon2Parallelism)
                .WithSalt(salt)
                .Build();

            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);

            var key = new byte[KeySize];
            //  пароль - байты ASCII, без перекодировки
            generator.GenerateBytes(System.Text.Encoding.ASCII.GetBytes(password), key);
            return key;
        }

        //  XChaCha20-Poly1305 = HChaCha20 для вывода подключа + обычный
        //  ChaCha20-Poly1305 (IETF) с nonce из четырёх нулей и хвоста исходного
        private static byte[] XChaCha20Poly1305Decrypt(byte[] key, byte[] nonce24, byte[] ad, byte[] cipher)
        {
            var subKeyNonce = new byte[16];
            Buffer.BlockCopy(nonce24, 0, subKeyNonce, 0, 16);
            var subKey = HChaCha20(key, subKeyNonce);

            var ietfNonce = new byte[12];
            Buffer.BlockCopy(nonce24, 16, ietfNonce, 4, 8);

            var aead = new ChaCha20Poly1305();
            aead.Init(false, new AeadParameters(new KeyParameter(subKey), TagSize * 8, ietfNonce, ad));

            var plain = new byte[aead.GetOutputSize(cipher.Length)];
            var length = aead.ProcessBytes(cipher, 0, cipher.Length, plain, 0);
            length += aead.DoFinal(plain, length);
            Array.Clear(subKey, 0, subKey.Length);

            if (length != plain.Length)
                Array.Resize(ref plain, length);

            return plain;
        }

        private static byte[] HChaCha20(byte[] key, byte[] nonce16)
        {
            var state = new uint[16];
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            for (var i = 0; i < 8; i++)
                state[4 + i] = BitConverter.ToUInt32(key, i * 4);
            for (var i = 0; i < 4; i++)
                state[12 + i] = BitConverter.ToUInt32(nonce16, i * 4);

            for (var i = 0; i < 10; i++)
            {
                QuarterRound(state, 0, 4, 8, 12);
                QuarterRound(state, 1, 5, 9, 13);
                QuarterRound(state, 2, 6, 10, 14);
                QuarterRound(state, 3, 7, 11, 15);
                QuarterRound(state, 0, 5, 10, 15);
                QuarterRound(state, 1, 6, 11, 12);
                QuarterRound(state, 2, 7, 8, 13);
                QuarterRound(state, 3, 4, 9, 14);
            }

            //  подключ - первые и последние четыре слова состояния, без сложения
            //  с исходным: этим HChaCha20 и отличается от обычного ChaCha20
            var result = new byte[32];
            for (var i = 0; i < 4; i++)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(state[i]), 0, result, i * 4, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(state[12 + i]), 0, result, 16 + i * 4, 4);
            }

            return result;
        }

        private static void QuarterRound(uint[] x, int a, int b, int c, int d)
        {
            x[a] += x[b]; x[d] = RotateLeft(x[d] ^ x[a], 16);
            x[c] += x[d]; x[b] = RotateLeft(x[b] ^ x[c], 12);
            x[a] += x[b]; x[d] = RotateLeft(x[d] ^ x[a], 8);
            x[c] += x[d]; x[b] = RotateLeft(x[b] ^ x[c], 7);
        }

        private static uint RotateLeft(uint value, int bits)
        {
            return (value << bits) | (value >> (32 - bits));
        }
    }
}
