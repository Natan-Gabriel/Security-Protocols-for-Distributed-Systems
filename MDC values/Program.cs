using System;
using System.IO;
using System.Security.Cryptography;

namespace MDC_values
{
    class Program
    {
        static MD5 md5 = System.Security.Cryptography.MD5.Create();

        static string readFile(string filename)
        {
            string text = "";
            try
            {
                text = System.IO.File.ReadAllText(@"C:\Users\Miriam\Desktop\facultate\UOradea\sem1\Security Protocols for Distributed Systems\MDC values\" + filename);
            }
            catch
            {
                Console.WriteLine("An error occurred while reading the file");
            }

            // Display the file contents to the console. Variable text is a string.
            //System.Console.WriteLine("Contents of WriteText.txt = {0}", text);
            return text;
        }

        static byte[] toByte(string input, string type)
        {
           
            if (type == "file")
            {
                input = System.IO.File.ReadAllText(@"C:\Users\Miriam\Desktop\facultate\UOradea\sem1\Security Protocols for Distributed Systems\MDC values\" + input);
            }

            return System.Text.Encoding.ASCII.GetBytes(input);

        }

        static string computeMDC(byte[] byte_array)
        {
            
            byte[] hashedValue = md5.ComputeHash(byte_array);
            return BitConverter.ToString(hashedValue);
        }

        static void Main(string[] args)
        {
            //Console.WriteLine("Hello World!");

            string s1 = computeMDC(toByte("Lorem ipsum dolor sit amet", "string"));
            Console.WriteLine(s1);

            string s2 = computeMDC(toByte("file1.txt", "file"));
            Console.WriteLine(s2);

            byte[] byte_array = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
            string s3 = computeMDC(byte_array);
            Console.WriteLine(s3);

        }



            /*string type = Console.ReadLine();
            if (type == "byte array")
            {

            }
            string input = Console.ReadLine();

            try
            {
                readFile("file1.txt");
            }
            catch
            {
                Console.WriteLine("An error occurred while reading the file");
            }
            readFile("file.txt");*/
        

        /*string input = "da";
        MD5 md5 = System.Security.Cryptography.MD5.Create();
        byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
        //byte[] hashedValue = md5.ComputeHash(inputBytes);
        byte[] hashedValue = md5.ComputeHash(inputBytes);
        //Console.WriteLine(System.Text.Encoding.ASCII.GetString(hashedValue));
        Console.WriteLine(BitConverter.ToString(hashedValue));*/

    /*static void Main(){

        const int arrayLength = 1000;

        // Create random data to write to the stream.
        byte[] dataArray = new byte[arrayLength];
        new Random().NextBytes(dataArray);

        BinaryWriter binWriter = new BinaryWriter(new MemoryStream());

        // Write the data to the stream.
        Console.WriteLine("Writing the data.");
        binWriter.Write(dataArray);

        // Create the reader using the stream from the writer.
        BinaryReader binReader =
            new BinaryReader(binWriter.BaseStream);

        // Set Position to the beginning of the stream.
        binReader.BaseStream.Position = 0;

        // Read and verify the data.
        byte[] verifyArray = binReader.ReadBytes(arrayLength);
        if (verifyArray.Length != arrayLength)
        {
            Console.WriteLine("Error writing the data.");
            return;
        }
        for (int i = 0; i < arrayLength; i++)
        {
            if (verifyArray[i] != dataArray[i])
            {
                Console.WriteLine("Error writing the data.");
                return;
            }
        }
        Console.WriteLine("The data was written and verified.");
    }*/
}
}
