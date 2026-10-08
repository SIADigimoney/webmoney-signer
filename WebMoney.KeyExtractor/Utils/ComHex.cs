//  Hex-представление чисел RSA-ключа (D и N), как его хранят классические модули WebMoney:
//  число - последовательность 16-битных слов, младшее слово первым, каждое
//  печатается как %04x. Старшие нулевые слова не печатаются (significance).

using System;
using System.Text;

namespace WebMoney.KeyExtractor.Utils
{
    internal static class ComHex
    {
        /// <summary>Little-endian байты -> hex по 16-битным словам, младшее первым.</summary>
        public static string ToComHex(byte[] littleEndian)
        {
            if (null == littleEndian)
                throw new ArgumentNullException(nameof(littleEndian));
            if (0 != littleEndian.Length % 2)
                throw new ArgumentException("Ожидается чётное число байтов (16-битные слова).", nameof(littleEndian));

            //  как significance(): старшие нулевые слова отбрасываются
            var words = littleEndian.Length / 2;
            while (words > 1 &&
                   0 == littleEndian[(words - 1) * 2] &&
                   0 == littleEndian[(words - 1) * 2 + 1])
                words--;

            var result = new StringBuilder(words * 4);
            for (var i = 0; i < words; i++)
            {
                var word = littleEndian[i * 2] | (littleEndian[i * 2 + 1] << 8);
                result.Append(word.ToString("x4"));
            }

            return result.ToString();
        }

        /// <summary>Hex по 16-битным словам, младшее первым -> little-endian байты.</summary>
        public static byte[] FromComHex(string hex)
        {
            if (null == hex)
                throw new ArgumentNullException(nameof(hex));
            if (0 != hex.Length % 4)
                throw new ArgumentException("Длина должна быть кратна 4 (16-битные слова).", nameof(hex));

            var result = new byte[hex.Length / 2];
            for (var i = 0; i < hex.Length / 4; i++)
            {
                var word = Convert.ToInt32(hex.Substring(i * 4, 4), 16);
                result[i * 2] = (byte)(word & 0xFF);
                result[i * 2 + 1] = (byte)(word >> 8);
            }

            return result;
        }
    }
}
