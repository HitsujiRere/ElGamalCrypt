using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ElGamalCrypt
{
    /// <summary>
    /// ElGamalCryptで使用する鍵
    /// </summary>
    /// <value>G</value>
    class ElGamalCryptKey
    {
        /// <summary>
        /// 公開鍵
        /// </summary>
        public (int q, int g, int y) PublicKey { get; set; }

        /// <summary>
        /// 秘密鍵
        /// </summary>
        public int SecretKey { get; set; }
    }
}
