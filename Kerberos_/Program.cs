/* Test test = new Test();
string myString = JsonConvert.SerializeObject(test);

string myStringEncrypted = DESImpl.EncryptDES(myString, new UnicodeEncoding(false, true, true).GetString(DESalg.Key));
string myStringDecrypted = DESImpl.DecryptDES(myStringEncrypted, new UnicodeEncoding(false, true, true).GetString(DESalg.Key));

Console.WriteLine("myStringDecrypted: " + myStringDecrypted);
            Test myInfoBlock = JsonConvert.DeserializeObject<Test>(myStringDecrypted);
Console.WriteLine(myInfoBlock.testFunction()); */


using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Text.RegularExpressions;

namespace Kerberos
{


    public class Test
    {
        public string testFunction()
        {
            //Console.WriteLine("Test");
            return "It worked";
        }
    }

    class Program
    {



        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            Client c = new Client();
            c.name = "Victor";
            Server s = new Server();
            Kerberos k = new Kerberos();
            c.initClient();
            c.sendMessage(s);

            DES DESalg = DES.Create("DES");
            DES another_one = DES.Create("DES");

            /*// Create a string to encrypt.
            string sData = "Here is some data to encrypt.";

            // Encrypt the string to an in-memory buffer.
            byte[] Data = DESImpl.EncryptTextToMemory(sData, DESalg.Key, DESalg.IV);
            Console.WriteLine(System.Text.Encoding.ASCII.GetString(Data));

            // Decrypt the buffer back to a string.
            string Final = DESImpl.DecryptTextFromMemory(Data, DESalg.Key, DESalg.IV);

            // Display the decrypted string to the console.
            Console.WriteLine(Final);
            Console.WriteLine(DateTime.Now.ToString("yyyyMMddHHmmssffff"));*/


            //Console.WriteLine(DESalg.IV);
            // WORKING EXAMPLE BELOW
            /*Test test = new Test();
            string myString = JsonConvert.SerializeObject(test);
            Console.WriteLine("myString is: " + myString);

            byte[] myStringEncrypted = DESImpl.EncryptTextToMemory(myString, DESalg.Key, another_one.IV);
            string myStringDecrypted = DESImpl.DecryptTextFromMemory(myStringEncrypted, DESalg.Key, another_one.IV);
            Console.WriteLine("myStringDecrypted: " + myStringDecrypted);

            Test myInfoBlock = JsonConvert.DeserializeObject<Test>(myStringDecrypted);
            Console.WriteLine(myInfoBlock.testFunction()); */

            /*Test test = new Test();
            string myString = JsonConvert.SerializeObject(test);
            //Console.WriteLine("myString is: " + myString);

            string myStringEncrypted = DESImpl.EncryptDES(myString, Convert.ToBase64String(DESalg.Key));
            string myStringDecrypted = DESImpl.DecryptDES(myStringEncrypted, Convert.ToBase64String(DESalg.Key));
            Console.WriteLine("myStringDecrypted: " + myStringDecrypted);

            Test myInfoBlock = JsonConvert.DeserializeObject<Test>(myStringDecrypted);
            Console.WriteLine(myInfoBlock.testFunction());*/

            /*Test test = new Test();
            string myString = JsonConvert.SerializeObject(test);

            string myStringEncrypted = DESImpl.EncryptDES(myString, DESImpl.ToHexString(DESalg.Key));
            string myStringDecrypted = DESImpl.DecryptDES(myStringEncrypted, DESImpl.ToHexString(DESalg.Key));

            Test myInfoBlock = JsonConvert.DeserializeObject<Test>(myStringDecrypted);
            Console.WriteLine(myInfoBlock.testFunction());*/


        }
    }

    public class Kerberos
    {
        static TGS tgs = new TGS();
        public static Dictionary<string, string> key_storage = new Dictionary<string, string>();
        public static Dictionary<TGS, string> tgs_key_storage = new Dictionary<TGS, string>();

        public static List<string> authenticateClient(Client c_identifier, TGS tgs_identifier)
        {
            string K_C = "";
            if (!key_storage.ContainsKey(c_identifier.name))
            {
                K_C = Convert.ToHexString(DES.Create("DES").Key);
                key_storage[c_identifier.name] = K_C;
            }
            else
            {
                K_C = key_storage[c_identifier.name];
            }

            Console.WriteLine("K_C: " + key_storage[c_identifier.name]);

            string K_TGS = "";
            if (!tgs_key_storage.ContainsKey(tgs_identifier))
            {
                K_TGS = Convert.ToHexString(DES.Create("DES").Key);
                tgs_key_storage[tgs_identifier] = K_TGS;
            }
            else
            {
                K_TGS = tgs_key_storage[tgs_identifier];
            }

            var l = new List<string>();

            string K_C_TGS = Convert.ToHexString(DES.Create("DES").Key);
            Console.WriteLine("K_C_TGS: " + K_C_TGS + "gata");
            l.Add(DESImpl.EncryptDES(K_C_TGS, K_C));

            Console.WriteLine("K_C_TGS: " + K_C_TGS);

            string tgs_serialized = JsonConvert.SerializeObject(tgs_identifier);
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(tgs_serialized, K_TGS), K_C));

            string c_serialized = JsonConvert.SerializeObject(c_identifier);
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(c_serialized, K_TGS), K_C));

            string adr_serialized = "192.168.0.0";
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(adr_serialized, K_TGS), K_C));

            string time_stamp = DateTime.Now.ToString("yyyyMMddHHmmssffff");
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(time_stamp, K_TGS), K_C));

            string life_time = DateTime.Now.ToString("1:00");
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(life_time, K_TGS), K_C));

            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(K_C_TGS, K_TGS), K_C));

            /*l.Add(tgs_identifier);
            l.Add(c_identifier);
            l.Add("192.168.0.0");
            l.Add(DateTime.Now.ToString("yyyyMMddHHmmssffff"));
            l.Add("1:00");
            l.Add("K C,TGS"); // encrypt with K TGS */

            return l;
        }

        static void Main1(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }


    public class TGS
    {
        public static Dictionary<string, string> server_key_storage = new Dictionary<string, string>();

        public List<string> authenticateClient(Server s_identifier, List<string> l2, List<string> l3)
        {

            string K_S = "";
            if (!server_key_storage.ContainsKey(s_identifier.name))
            {
                K_S = Convert.ToHexString(DES.Create("DES").Key);
                server_key_storage[s_identifier.name] = K_S;
            }
            else
            {
                K_S = server_key_storage[s_identifier.name];
            }

            string K_TGS = Kerberos.tgs_key_storage[this];
            string EK_TGS__K_C_TGS = l2[5];
            string K_C_TGS = DESImpl.DecryptDES(EK_TGS__K_C_TGS, K_TGS);
            //l1.RemoveAt(0);

            var l = new List<string>(); // Ticket C,S

            string s_serialized = JsonConvert.SerializeObject(s_identifier);
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(s_serialized, K_S), K_C_TGS));

            string c_serialized_encrypted = l3[0];
            string c_serialized = DESImpl.DecryptDES(c_serialized_encrypted, K_C_TGS);
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(c_serialized, K_S), K_C_TGS));

            string adr_serialized = "192.168.0.0";
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(adr_serialized, K_S), K_C_TGS));

            string time_stamp = DateTime.Now.ToString("yyyyMMddHHmmssffff");
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(time_stamp, K_S), K_C_TGS));

            string life_time = DateTime.Now.ToString("1:00");
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(life_time, K_S), K_C_TGS));

            string K_C_S = Convert.ToHexString(DES.Create("DES").Key);
            l.Add(DESImpl.EncryptDES(DESImpl.EncryptDES(K_C_S, K_S), K_C_TGS));

            l.Add(DESImpl.EncryptDES(K_C_S, K_C_TGS));

            return l;
        }

        static void Main1(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }

    public class Server
    {
        static Dictionary<Client, string> client_key_storage = new Dictionary<Client, string>();
        public string name = "da";

        public void authenticateClient(List<string> l5, List<string> l6)
        {

            string K_S = TGS.server_key_storage[this.name];
            string EK_S__K_C_S = l5[5];
            string K_C_S = DESImpl.DecryptDES(EK_S__K_C_S, K_S);

            // check if client from l5 and l6 is the same

            string EK_S__C = l5[1];
            string C = DESImpl.DecryptDES(EK_S__C, K_S);
            Client c = JsonConvert.DeserializeObject<Client>(C);
            client_key_storage[c] = K_C_S;

            Console.WriteLine("K_C_S on server: " + K_C_S);
        }

        public string sendMessageToServer(string s)
        {
            Console.WriteLine("Server received: " + s);
            return "Hello client";

        }


        static void Main1(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }

    public class Client
    {

        static Kerberos kerberos;
        static TGS tgs = new TGS();
        static Server server = new Server();
        string K_C_S;
        public string name = "";


        public void initClient()
        {
            Console.WriteLine("Hello World!");
            List<string> l1 = Kerberos.authenticateClient(this, tgs);

            /////////////////////////////////////////////////////////

            string K_C = Kerberos.key_storage[this.name];
            Console.WriteLine("K_C: " + K_C);
            string E_KC_K_C_TGS = l1[0];
            Console.WriteLine("K_C_TGS: " + DESImpl.DecryptDES(E_KC_K_C_TGS, K_C));
            string K_C_TGS = DESImpl.DecryptDES(E_KC_K_C_TGS, K_C);
            l1.RemoveAt(0);


            List<string> l2 = new List<string>();

            foreach (string elem in l1)
            {
                l2.Add(DESImpl.DecryptDES(elem, K_C));
            }

            List<string> l3 = new List<string>();

            Console.WriteLine("K_C_TGS: " + K_C_TGS);
            string c_serialized = JsonConvert.SerializeObject(this);
            l3.Add(DESImpl.EncryptDES(c_serialized, K_C_TGS));

            string adr_serialized = "192.168.0.0";
            l3.Add(DESImpl.EncryptDES(adr_serialized, K_C_TGS));

            string time_stamp = DateTime.Now.ToString("yyyyMMddHHmmssffff");
            l3.Add(DESImpl.EncryptDES(time_stamp, K_C_TGS));

            List<string> l4 = tgs.authenticateClient(server, l2, l3); // trebuie sa iau tgs decriptat, NU ASTA!


            //////////////////////////////////////////////////////////////

            string EK_C_TGS__K_C_S = l4[5];
            K_C_S = DESImpl.DecryptDES(EK_C_TGS__K_C_S, K_C_TGS);

            List<string> l5 = new List<string>();

            foreach (string elem in l4)
            {
                l5.Add(DESImpl.DecryptDES(elem, K_C_TGS));
            }

            List<string> l6 = new List<string>();

            c_serialized = JsonConvert.SerializeObject(this);
            l6.Add(DESImpl.EncryptDES(c_serialized, K_C_S));

            adr_serialized = "192.168.0.0";
            l6.Add(DESImpl.EncryptDES(adr_serialized, K_C_S));

            time_stamp = DateTime.Now.ToString("yyyyMMddHHmmssffff");
            l6.Add(DESImpl.EncryptDES(time_stamp, K_C_S));

            server.authenticateClient(l5, l6);

            Console.WriteLine("K_C_S in client: " + K_C_S);
        }

        public void sendMessage(Server s)
        {
            Console.WriteLine(s.sendMessageToServer("Hello Server"));
        }



    }

    //System.Text.Encoding.ASCII.GetBytes(input)
    //System.Text.Encoding.ASCII.GetString(hashedValue)

    // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.des.create?view=net-6.0
    class DESImpl
    {
        //static DES des_alg = DES.Create("DES");
        static DES another_one = DES.Create("DES");
        public static UnicodeEncoding enc = new UnicodeEncoding(false, true, true);

        /* public static string ToHexString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        public static byte[] FromHexString(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }*/



        public static string EncryptDES(string myString, string key)
        {
            //DES des_alg = DES.Create("DES");
            key = key.Substring(0, 16);
            Console.WriteLine("WHATT: " + "   A String   ".Trim());
            Console.WriteLine("key: " + key.Trim() + "gata");
            byte[] byte_key = Convert.FromHexString(key.Trim());
            byte[] myStringEncrypted = EncryptTextToMemory(myString, byte_key, another_one.IV);
            //byte[] myStringEncrypted = EncryptTextToMemory(myString, bkey, another_one.IV);
            return Convert.ToHexString(myStringEncrypted);
            //return myStringEncrypted;


        }

        public static string DecryptDES(string myStringEncrypted, string key)
        {
            //DES des_alg = DES.Create("DES");
            key = key.Substring(0, 16);
            byte[] byte_key = Convert.FromHexString(key);
            myStringEncrypted = Regex.Replace(myStringEncrypted, @"[^A-F0-9]", "");
            Console.WriteLine("myStringEncrypted: " + Regex.Replace(myStringEncrypted, @"[^A-F0-9]", "") + "hmm");
            byte[] byte_myStringEncrypted = Convert.FromHexString(myStringEncrypted);
            string myStringDecrypted = DecryptTextFromMemory(byte_myStringEncrypted, byte_key, another_one.IV);
            //string myStringDecrypted = DecryptTextFromMemory(byte_myStringEncrypted, bkey, another_one.IV);
            return myStringDecrypted;

            /*byte[] myStringEncrypted = DESImpl.EncryptTextToMemory(myString, DESalg.Key, another_one.IV);
            string myStringDecrypted = DESImpl.DecryptTextFromMemory(myStringEncrypted, DESalg.Key, another_one.IV);
            Console.WriteLine("myStringDecrypted: " + myStringDecrypted);

            Test myInfoBlock = JsonConvert.DeserializeObject<Test>(myStringDecrypted);*/
        }

        /*public static byte[] EncryptDES(string myString, string key, byte[] bkey)
        {
            //DES des_alg = DES.Create("DES");
            //byte[] byte_key = System.Text.Encoding.ASCII.GetBytes(key);
            //byte[] myStringEncrypted = EncryptTextToMemory(myString, byte_key, des_alg.IV);
            byte[] myStringEncrypted = EncryptTextToMemory(myString, bkey, another_one.IV);
            //return System.Text.Encoding.ASCII.GetString(myStringEncrypted);
            return myStringEncrypted;


        }

        public static string DecryptDES(byte[] myStringEncrypted, string key, byte[] bkey)
        {
            //DES des_alg = DES.Create("DES");
            //byte[] byte_key = System.Text.Encoding.ASCII.GetBytes(key);
            //byte[] byte_myStringEncrypted = System.Text.Encoding.ASCII.GetBytes(myStringEncrypted);
            //string myStringDecrypted = DecryptTextFromMemory(byte_myStringEncrypted, byte_key, des_alg.IV);
            string myStringDecrypted = DecryptTextFromMemory(myStringEncrypted, bkey, another_one.IV);
            return myStringDecrypted;

           
    }*/

        /*public static byte[] EncryptDES(string myString, string key, byte[] bkey)
        {
            DES des_alg = DES.Create("DES");
            byte[] byte_key = System.Text.Encoding.ASCII.GetBytes(key);
            //byte[] myStringEncrypted = EncryptTextToMemory(myString, byte_key, des_alg.IV);
            byte[] myStringEncrypted = EncryptTextToMemory(myString, bkey, des_alg.IV);
            //return System.Text.Encoding.ASCII.GetString(myStringEncrypted);
            return myStringEncrypted;


        }

        public static string DecryptDES(byte[] myStringEncrypted, string key, byte[] bkey)
        {
            DES des_alg = DES.Create("DES");
            byte[] byte_key = System.Text.Encoding.ASCII.GetBytes(key);
            //byte[] byte_myStringEncrypted = System.Text.Encoding.ASCII.GetBytes(myStringEncrypted);
            //string myStringDecrypted = DecryptTextFromMemory(byte_myStringEncrypted, byte_key, des_alg.IV);
            string myStringDecrypted = DecryptTextFromMemory(byte_myStringEncrypted, bkey, des_alg.IV);
            return myStringDecrypted;

        }*/

        public static byte[] EncryptTextToMemory(string Data, byte[] Key, byte[] IV)
        {
            try
            {
                // Create a MemoryStream.
                MemoryStream mStream = new MemoryStream();

                // Create a new DES object.
                DES DESalg = DES.Create();

                // Create a CryptoStream using the MemoryStream
                // and the passed key and initialization vector (IV).
                CryptoStream cStream = new CryptoStream(mStream,
                    DESalg.CreateEncryptor(Key, IV),
                    CryptoStreamMode.Write);

                // Convert the passed string to a byte array.
                byte[] toEncrypt = new ASCIIEncoding().GetBytes(Data);

                // Write the byte array to the crypto stream and flush it.
                //cStream.Write(toEncrypt);
                cStream.Write(toEncrypt, 0, toEncrypt.Length);
                cStream.FlushFinalBlock();

                // Get an array of bytes from the
                // MemoryStream that holds the
                // encrypted data.
                byte[] ret = mStream.ToArray();

                // Close the streams.
                cStream.Close();
                mStream.Close();

                // Return the encrypted buffer.
                return ret;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred1: {0}", e.Message);
                return null;
            }
        }

        public static string DecryptTextFromMemory(byte[] Data, byte[] Key, byte[] IV)
        {
            try
            {
                // Create a new MemoryStream using the passed
                // array of encrypted data.
                MemoryStream msDecrypt = new MemoryStream(Data);

                // Create a new DES object.
                DES DESalg = DES.Create();

                // Create a CryptoStream using the MemoryStream
                // and the passed key and initialization vector (IV).
                CryptoStream csDecrypt = new CryptoStream(msDecrypt,
                    DESalg.CreateDecryptor(Key, IV),
                    CryptoStreamMode.Read);

                // Create buffer to hold the decrypted data.
                byte[] fromEncrypt = new byte[Data.Length];

                // Read the decrypted data out of the crypto stream
                // and place it into the temporary buffer.
                csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length);

                //Convert the buffer into a string and return it.
                return new ASCIIEncoding().GetString(fromEncrypt);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred2: {0}", e.Message);
                return null;
            }
        }
    }
}
