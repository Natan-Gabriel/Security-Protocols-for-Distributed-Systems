using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Linq;

namespace Simplified_Kerberos
{
    public class Test
    {
        public string testFunction()
        {
            //Console.WriteLine("Test");
            return "It worked";
        }
    }

    public class ListBox
    {
        public List<string> ticket_b;
        public List<string> second_list;

        public ListBox(List<string> _ticket_b, List<string> _second_list)
        {
            ticket_b = _ticket_b;
            second_list = _second_list;
        }
    }

    class Program
    {



        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            DateTime utcTime = DateTime.UtcNow;
            DateTime l = new DateTime(2022, 1, 23, 21, 30, 0);
            TimeSpan twoAndAHalfHours = new TimeSpan(12, 30, 0);
            l = l.Add(twoAndAHalfHours);

            DateTime localTime = DateTime.Now;

            Console.WriteLine("utcTime: " + utcTime);

            const string FMT = "O";
            string strDate = utcTime.ToString(FMT);
            utcTime = DateTime.ParseExact(strDate, FMT, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

            Console.WriteLine("utcTime: " + utcTime);

            Console.WriteLine("Difference between {0} and {1} time: {2}:{3} hours",
                              localTime.Kind,
                              utcTime.Kind,
                              l - utcTime,
                              utcTime < localTime);

            /*string strin = "    C   Sharp       ";
            strin = Regex.Replace(strin, @"s", "");
            Console.WriteLine(strin);*/

            /*Client c = new Client();
            c.name = "Victor";
            Server s = new Server();
            Kerberos k = new Kerberos();
            c.initClient();
            c.sendMessage(s);

            DES DESalg = DES.Create("DES");
            DES another_one = DES.Create("DES");*/


            /*string K_AT = Convert.ToHexString(DES.Create("DES").Key);
            string K_BT = Convert.ToHexString(DES.Create("DES").Key);*/

            KerberosT t = new KerberosT();
            ServerB b = new ServerB();
            ClientA a = new ClientA();

            string K_AT = Convert.ToHexString(DES.Create("DES").Key); // share K_AT
            t.setK_AT(K_AT);
            a.setK_AT(K_AT);

            string K_BT = Convert.ToHexString(DES.Create("DES").Key); // share K_BT
            t.setK_BT(K_BT);
            b.setK_BT(K_BT);

            List<string> list = a.step_1("client", "server");
            ListBox listBox = t.step_2(list);
            ListBox listBox2 = a.step_3(list, listBox);
            string str = b.step_4(listBox2);

            Console.WriteLine("str: " + str);



        }
    }

    public class KerberosT
    {
        /*static TGS tgs = new TGS();
        public static Dictionary<string, string> key_storage = new Dictionary<string, string>();
        public static Dictionary<TGS, string> tgs_key_storage = new Dictionary<TGS, string>();*/

        public static string FMT = "O";

        string K_AT, K_BT;
        string l; // valability period

        public void setK_AT(string key)
        {
            K_AT = key;
        }

        public void setK_BT(string key)
        {
            K_BT = key;
        }


        public ListBox step_2(List<string> list)
        {

            string a = list[0];
            string b = list[1];
            string n_A = list[2];


            var ticket_b = new List<string>();
            string k = Convert.ToHexString(DES.Create("DES").Key); // generate session key k
            
            DateTime expiry_time = DateTime.Now;
            TimeSpan thirty_minutes = new TimeSpan(0, 0, 30, 0, 0); // the ticket will be valid 30 minutes 
            //TimeSpan thirty_minutes = new TimeSpan(0, 0, 0, 0, 1); // the ticket will be valid 1 milisecond 
            expiry_time = expiry_time.Add(thirty_minutes);

            l = expiry_time.ToString(FMT);
            
            Console.WriteLine("l is: " + l + "end");

            ticket_b.Add(DESImpl.EncryptDES(k, K_BT));
            ticket_b.Add(DESImpl.EncryptDES(a, K_BT));
            ticket_b.Add(DESImpl.EncryptDES(l, K_BT));

            var second_list = new List<string>();
            second_list.Add(DESImpl.EncryptDES(k, K_AT));
            second_list.Add(DESImpl.EncryptDES(n_A, K_AT));
            Console.WriteLine("n_A encrypted: " + DESImpl.EncryptDES(n_A, K_AT));
            second_list.Add(DESImpl.EncryptDES(l, K_AT));
            second_list.Add(DESImpl.EncryptDES(b, K_AT));

            return new ListBox(ticket_b, second_list);
        }


        public static List<string> authenticateClient()
        {
            
            var l = new List<string>();
            return l;
        }

    }


    public class ServerB
    {
        /*static TGS tgs = new TGS();
        public static Dictionary<string, string> key_storage = new Dictionary<string, string>();
        public static Dictionary<TGS, string> tgs_key_storage = new Dictionary<TGS, string>();*/

        //static string FMT = "O";

        static string k = Convert.ToHexString(DES.Create("DES").Key);

        string K_BT;

        public void setK_BT(string key)
        {
            K_BT = key;
        }


        public string step_4(ListBox listBox)
        {
            //if checks pass
            List<string> ticket_b = listBox.ticket_b;
            List<string> second_list = listBox.second_list;

            List<string> ticket_b_decrypted = new List<string>();

            foreach(var elem in ticket_b)
            {
                ticket_b_decrypted.Add(DESImpl.DecryptDES(elem, K_BT));
            }

            string k = ticket_b_decrypted[0];

            List<string> authenticator_decrypted = new List<string>();
            foreach (var elem in second_list)
            {
                authenticator_decrypted.Add(DESImpl.DecryptDES(elem, k));
            }

            Console.WriteLine("ticket_b_decrypted.Count: " + ticket_b_decrypted.Count);
            Console.WriteLine("authenticator_decrypted.Count: " + authenticator_decrypted.Count);

            Console.WriteLine("A in ticket: " + ticket_b_decrypted[1] + "end");
            Console.WriteLine("A in authenticator: " + authenticator_decrypted[0] + "end");

            if (ticket_b_decrypted[1] == authenticator_decrypted[0])  // check if "A" is the same in the ticket and in the authenticator
                Console.WriteLine("A in ticket and in authenticator are the same!");

            string t_A = authenticator_decrypted[1];
            //Console.WriteLine("l is: " + l + "end") ;
            DateTime timestamp_in_A = DateTime.ParseExact(t_A, KerberosT.FMT, CultureInfo.InvariantCulture);

            if (timestamp_in_A < DateTime.Now) // check if t_A from authenticator is valid
                Console.WriteLine("t_A is valid!");

            string l = ticket_b_decrypted[2];
            Console.WriteLine("l is: " + l + "end") ;
            DateTime expiry_time = DateTime.ParseExact(l, KerberosT.FMT, CultureInfo.InvariantCulture);

            Console.WriteLine("expiry_time is: " + expiry_time);

            if (DateTime.Now < expiry_time) // check if the current time in B is valid with respect to expiry time L
                Console.WriteLine("The ticket is still valid");
            else
                Console.WriteLine("The ticket expired");

           

            /*string aux = ticket_b_decrypted[1];
            if (!aux[aux.Length - 1].Equals(' '))
                Console.WriteLine(aux[aux.Length - 1] + "Last char is not empty!");*/


            Console.WriteLine("Successful authentication!");

            //time checking

            return second_list[1]; //encrypted t_a

        }


        public static List<string> authenticateClient()
        {

            var l = new List<string>();
            return l;
        }

    }

    public class ClientA
    {
        /*static TGS tgs = new TGS();
        public static Dictionary<string, string> key_storage = new Dictionary<string, string>();
        public static Dictionary<TGS, string> tgs_key_storage = new Dictionary<TGS, string>();*/

        string K_AT, n_A, k, valability_period;

        public void setK_AT(string key)
        {
            K_AT = key;
        }

        public List<string> step_1(string a, string b)
        {
            n_A = DESImpl.generateNonce();
            var l = new List<string>();
            l.Add(a);
            l.Add(b);
            l.Add(n_A);
            return l;
        }


        public ListBox step_3(List<string> list, ListBox listBox)
        {

            List<string> ticket_b = listBox.ticket_b;
            List<string> second_list = listBox.second_list;

            List<string> authenticator = new List<string>();

           
            var a = list[0];
            k = DESImpl.DecryptDES(second_list[0], K_AT);
            string n_A_received = DESImpl.DecryptDES(second_list[1], K_AT);
            Console.WriteLine("n_A_received encrypted : " + second_list[1] + "end");
            valability_period = DESImpl.DecryptDES(second_list[2], K_AT);
            string b_identifier = DESImpl.DecryptDES(second_list[3], K_AT);
            Console.WriteLine("n_A: " + n_A + "end");
            Console.WriteLine("n_A_received: " + n_A_received.Trim() + "end");

            if (!n_A.Equals(n_A_received))
                throw new Exception("the nonce sent is not equal with the received one!");
            else
                Console.WriteLine("Good!!");


            DateTime expiry_time = DateTime.Now;
            string t_a =  expiry_time.ToString(KerberosT.FMT);

            authenticator.Add(DESImpl.EncryptDES(a, k));
            authenticator.Add(DESImpl.EncryptDES(t_a, k));

            return new ListBox(ticket_b, authenticator);
        }


        public static List<string> authenticateClient()
        {

            var l = new List<string>();
            return l;
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
        private static Random random = new Random();

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

        //https://sqlsteve.wordpress.com/2014/04/23/how-to-create-a-nonce-in-c/
        public static string generateNonce() 
        {
            const string chars = "0123456789";
            return new string(Enumerable.Repeat(chars, 40)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }


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
            return Regex.Replace(myStringDecrypted, @"[^A-Za-z0-9+-:.+ ]+", ""); // myStringDecrypted.Trim();

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

















/*static void Main(string[] args)
{
    Console.WriteLine("Hello World!");

    *//*Client c = new Client();
    c.name = "Victor";
    Server s = new Server();
    Kerberos k = new Kerberos();
    c.initClient();
    c.sendMessage(s);

    DES DESalg = DES.Create("DES");
    DES another_one = DES.Create("DES");*/


    /*string K_AT = Convert.ToHexString(DES.Create("DES").Key);
    string K_BT = Convert.ToHexString(DES.Create("DES").Key);*//*

    List<string> list = Kerberos.step_1("client", "server");
    ListBox listBox = Kerberos.step_2(list);
    ListBox listBox2 = Kerberos.step_3(list, listBox);
    string str = Kerberos.step_4(listBox2);
    Console.WriteLine("str: " + str);



}
    }

    public class Kerberos
{
    *//*static TGS tgs = new TGS();
    public static Dictionary<string, string> key_storage = new Dictionary<string, string>();
    public static Dictionary<TGS, string> tgs_key_storage = new Dictionary<TGS, string>();*//*

    static string K_AT = Convert.ToHexString(DES.Create("DES").Key);
    static string K_BT = Convert.ToHexString(DES.Create("DES").Key);
    static string k = Convert.ToHexString(DES.Create("DES").Key);

    public static List<string> step_1(string a, string b)
    {
        string n_A = DESImpl.generateNonce();
        var l = new List<string>();
        l.Add(a);
        l.Add(b);
        l.Add(n_A);
        return l;
    }

    public static ListBox step_2(List<string> list)
    {

        string a = list[0];
        string b = list[0];
        string n_A = list[0];


        var ticket_b = new List<string>();
        var l = ""; // to change

        ticket_b.Add(DESImpl.EncryptDES(k, K_BT));
        ticket_b.Add(DESImpl.EncryptDES(a, K_BT));
        ticket_b.Add(DESImpl.EncryptDES(l, K_BT));

        var second_list = new List<string>();
        second_list.Add(DESImpl.EncryptDES(k, K_AT));
        second_list.Add(DESImpl.EncryptDES(n_A, K_AT));
        second_list.Add(DESImpl.EncryptDES(l, K_AT));
        second_list.Add(DESImpl.EncryptDES(b, K_AT));

        return new ListBox(ticket_b, second_list);
    }

    public static ListBox step_3(List<string> list, ListBox listBox)
    {

        List<string> ticket_b = listBox.ticket_b;
        List<string> second_list = listBox.second_list;

        List<string> authenticator = new List<string>();

        var t_a = ""; // to change
        var a = list[0];
        authenticator.Add(DESImpl.EncryptDES(a, k));
        authenticator.Add(DESImpl.EncryptDES(t_a, k));

        return new ListBox(ticket_b, authenticator);
    }

    public static string step_4(ListBox listBox)
    {
        //if checks pass
        List<string> second_list = listBox.second_list;

        var t_a = second_list[1]; //encrypted t_a
        return t_a;

    }*/

















