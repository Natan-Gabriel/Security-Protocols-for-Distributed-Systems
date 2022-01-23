using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lamport_Scheme
{

    public class KeyBox
    {
        public byte[][] private_key_1;
        public byte[][] private_key_2;
        public byte[][] public_key_1;
        public byte[][] public_key_2;

        public KeyBox(byte[][] _private_key_1, byte[][] _private_key_2, byte[][] _public_key_1, byte[][] _public_key_2)
        {
            private_key_1 = _private_key_1;
            private_key_2 = _private_key_2;
            public_key_1 = _public_key_1;
            public_key_2 = _public_key_2;
        }
    }

    class MessageBox
    {
        public string message;
        public byte[][] signature;

        public MessageBox(string _message, byte[][] _signature)
        {
            message = _message;
            signature = _signature;
        }
    }

    class Program
    {

        static SHA256 sha256 = System.Security.Cryptography.SHA256.Create();

        // https://stackoverflow.com/questions/1344221/how-can-i-generate-random-alphanumeric-strings
        public static byte[] random256Bits()
        {
            
            var r = new byte[32];
            var random = new Random();
            random.NextBytes(r);

            return r;
        }

        static KeyBox keyGeneration()
        {
            var private_key_1 = new byte[256][];
            var private_key_2 = new byte[256][];

            var public_key_1 = new byte[256][];
            var public_key_2 = new byte[256][];


            for (int i = 0; i < 256; i++)
            {
                private_key_1[i] = new byte[32]; // EACH KEY HAS 256 bits = 32 * 8
                private_key_2[i] = new byte[32];

                private_key_1[i] = random256Bits();
                private_key_2[i] = random256Bits();
            }


            for (int i = 0; i < 256; i++)
            {
                public_key_1[i] = new byte[32];
                public_key_2[i] = new byte[32];

                public_key_1[i] = sha256.ComputeHash(private_key_1[i]);
                public_key_2[i] = sha256.ComputeHash(private_key_2[i]);
            }

            return new KeyBox(private_key_1, private_key_2, public_key_1, public_key_2);

        }

        static MessageBox signatureGeneration(string message, byte[][] private_key_1, byte[][] private_key_2)
        {

            byte[] hashed_message = sha256.ComputeHash(Encoding.ASCII.GetBytes(message));
            var signature = new byte[256][];

            BitArray bits = new BitArray(hashed_message);
            for (int i = 0; i < bits.Length; i++)
            {
                signature[i] = new byte[32]; // EACH KEY HAS 256 bits = 32 * 8
                
                if (bits[i])
                    signature[i] = private_key_2[i];
                else
                    signature[i] = private_key_1[i];
            }


            return new MessageBox(message, signature);

        }


        static bool signatureVerification(MessageBox messageBox, byte[][] public_key_1, byte[][] public_key_2)
        {

            string message = messageBox.message;
            byte[][] signature = messageBox.signature;

            byte[] hashed_message = sha256.ComputeHash(Encoding.ASCII.GetBytes(message));

            var signature_in_verification = new byte[256][];

            BitArray bits = new BitArray(hashed_message);
            for (int i = 0; i < bits.Length; i++)
            {
                signature_in_verification[i] = new byte[32]; // EACH KEY HAS 256 bits = 32 * 8

                if (bits[i])
                    signature_in_verification[i] = public_key_2[i];
                else
                    signature_in_verification[i] = public_key_1[i];
            }
            
            var hashed_signature = new byte[256][];
            for (int i = 0; i < 256; i++)
            {
                hashed_signature[i] = new byte[32];
                hashed_signature[i] = sha256.ComputeHash(signature[i]);
            }

            for (int i = 0; i < 256; i++)
            {
                if (!StructuralComparisons.StructuralEqualityComparer.Equals(hashed_signature[i], signature_in_verification[i]))
                    return false;
            }

            //Console.WriteLine("hashed_signature[0]: " + BitConverter.ToString(hashed_signature[0]));
            //Console.WriteLine("signature_in_verification[0]: " + BitConverter.ToString(signature_in_verification[0]));

            return true;
        }


        static void Main(string[] args)
        {

            KeyBox keyBox = keyGeneration();

            MessageBox messageBox = signatureGeneration("First message", keyBox.private_key_1, keyBox.private_key_2);

            bool boolean = signatureVerification(messageBox, keyBox.public_key_1, keyBox.public_key_2);

            if (boolean)
            {
                Console.WriteLine("Successful authentication: the signature verification passed");

            }

        }
    }
}
