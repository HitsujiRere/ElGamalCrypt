using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ElGamalCrypt
{
    /// <summary>
    /// ElGamal暗号を行うクラス
    /// </summary>
    static class ElGamalCrypt
    {
        private static Random rnd = new Random();

        /// <summary>
        /// 暗号化する
        /// </summary>
        /// <param name="m">平文</param>
        /// <param name="key">鍵</param>
        /// <returns>暗号文</returns>
        public static (int c1, int c2) Encrypt(int m, ElGamalCryptKey key)
        {
            var r = rnd.Next(0, key.PublicKey.q - 1);

            var c1 = ModPow(key.PublicKey.g, r, key.PublicKey.q);
            var c2 = (m * ModPow(key.PublicKey.y, r, key.PublicKey.q)) % key.PublicKey.q;

            return (c1, c2);
        }

        /// <summary>
        /// 復号する
        /// </summary>
        /// <param name="c">暗号文</param>
        /// <param name="key">鍵</param>
        /// <returns>復号文</returns>
        public static int Decrypt((int c1, int c2) c, ElGamalCryptKey key)
        {
            return c.c2 * ModPow(ModInv(c.c1, key.PublicKey.q), key.SecretKey, key.PublicKey.q) % key.PublicKey.q;
        }

        /// <summary>
        /// 鍵を生成する
        /// </summary>
        /// <returns>鍵</returns>
        public static ElGamalCryptKey CreateKey()
        {
            var (q, g) = CreateG();

            var x = rnd.Next(0, q - 1);

            var y = ModPow(g, x, q);

            return new ElGamalCryptKey()
            {
                PublicKey = (q, g, y),
                SecretKey = x
            };
        }

        /// <summary>
        /// 巡回群Gを生成する
        /// </summary>
        /// <returns>Gの位相q, Gのランダムな生成元g</returns>
        private static (int q, int g) CreateG()
        {
            int q = 0, p = 0;

            // 素数p, 素数qを生成する
            while (true)
            {
                p = CreatePrime(int.MaxValue / 1000, (int.MaxValue - 1) / 2);
                q = 2 * p + 1;
                if (IsPrime(q))
                {
                    break;
                }
            }

            var g = CreateOrigin(p, q);

            return (q, g);
        }

        /// <summary>
        /// 範囲内のランダムな素数を返します
        /// </summary>
        /// <param name="min">最小値</param>
        /// <param name="max">最大値</param>
        /// <returns>範囲内のランダムな素数</returns>
        private static int CreatePrime(int min, int max)
        {
            while (true)
            {
                int num = rnd.Next(min, max);

                if (IsPrime(num))
                {
                    return num;
                }
            }
        }

        /// <summary>
        /// 素数かどうか判定します
        /// </summary>
        /// <param name="num">判定する数</param>
        /// <returns>素数かどうか</returns>
        private static bool IsPrime(int num)
        {
            if (num < 2)
                return false;
            else if (num == 2)
                return true;
            else if (num % 2 == 0)
                return false;

            for (int i = 3; i * i <= num; i += 2)
            {
                if (num % i == 0)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// 原始元を生成する
        /// </summary>
        /// <param name="p">素数p</param>
        /// <param name="q">素数q=2p+1</param>
        /// <returns>原始元</returns>
        private static int CreateOrigin(int p, int q)
        {
            for (int i = 2; i < q; i++)
            {
                var g = i % q;
                if (g != 1 && (g * g) % q != 1 && ModPow(g, q, p) != 1)
                {
                    return g;
                }
            }

            return -1;
        }

        /// <summary>
        /// べき乗の余剰を計算する
        /// </summary>
        /// <param name="a">底</param>
        /// <param name="n">指数</param>
        /// <param name="mod">余剰</param>
        /// <returns>べき乗の余剰</returns>
        private static int ModPow(long a, long n, long mod)
        {
            long res = 1;
            while (n > 0)
            {
                if ((n & 1) == 1) res = (res * a) % mod;
                a = (a * a) % mod;
                n >>= 1;
            }
            return (int)res;
        }

        /// <summary>
        /// aの逆元を求める
        /// </summary>
        /// <param name="a">低</param>
        /// <param name="m">余剰</param>
        /// <returns>aの逆元</returns>
        private static int ModInv(long a, long m)
        {
            long b = m, u = 1, v = 0;
            while (b > 0)
            {
                long t = a / b;
                a -= t * b; Swap(ref a, ref b);
                u -= t * v; Swap(ref u, ref v);
            }
            u %= m;
            if (u < 0) u += m;
            return (int)u;
        }

        /// <summary>
        /// aとbの値を交換する
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="a"></param>
        /// <param name="b"></param>
        private static void Swap<T>(ref T a, ref T b)
        {
            T tmp = a;
            a = b;
            b = tmp;
        }
    }
}
