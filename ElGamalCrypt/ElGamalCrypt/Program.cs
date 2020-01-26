using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ElGamalCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            var rnd = new Random();

            while (true)
            {
                var key = ElGamalCrypt.CreateKey();
                var m = 331;

                Console.WriteLine("pk = {0}", key.PublicKey);
                Console.WriteLine("sk = {0}", key.SecretKey);
                Console.WriteLine(" m = {0}", m);

                var c = ElGamalCrypt.Encrypt(m, key);

                Console.WriteLine(" c = {0}", c);

                var m2 = ElGamalCrypt.Decrypt(c, key);

                Console.WriteLine("m' = {0}", m2);


                Console.ReadLine();
            }
        }
    }
}
