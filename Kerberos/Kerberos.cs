using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Diagnostics;

namespace Kerberos
{
    class Program
    {



        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            DES DESalg = DES.Create("DES");

            // Create a string to encrypt.
            string sData = "Here is some data to encrypt.";

            // Encrypt the string to an in-memory buffer.
            byte[] Data = DESImpl.EncryptTextToMemory(sData, DESalg.Key, DESalg.IV);
            Console.WriteLine(System.Text.Encoding.ASCII.GetString(Data));

            // Decrypt the buffer back to a string.
            string Final = DESImpl.DecryptTextFromMemory(Data, DESalg.Key, DESalg.IV);

            // Display the decrypted string to the console.
            Console.WriteLine(Final);
            Console.WriteLine(DateTime.Now.ToString("yyyyMMddHHmmssffff"));
        }
    }

    public class Kerberos
    {
        static TGS tgs;

        public static List<string> authenticateClient(string c_identifier, string tgs_identifier)
        {
            var l = new List<string>();
            l.Add(tgs_identifier);
            l.Add(c_identifier);
            l.Add("192.168.0.0");
            l.Add(DateTime.Now.ToString("yyyyMMddHHmmssffff"));
            l.Add("1:00");
            l.Add("K C,TGS"); // encrypt with K TGS

            return l;
        }

        static void Main1(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }


    class TGS
    {



        static void Main1(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }

    class Server
    {



        static void Main1(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }

    class Client
    {

        static Kerberos kerberos;
        static TGS tgs;


        static void Main1(string[] args)
        {
            Console.WriteLine("Hello World!");
            List<string> l = Kerberos.authenticateClient("string c_identifier", "string tgs_identifier");



        }
    }

    class DESImpl
    {
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
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
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
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
        }
    }
}
