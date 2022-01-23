using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

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

        static async Task<string> computeMDC(string input, string type)
        {

            byte[] byte_array = toByte(input, type);
            byte[] hashedValue = md5.ComputeHash(byte_array);
            //await Task.Delay(10000);
            return "The corresponding MDC hash value for the " + type + " " + input + " is: " + BitConverter.ToString(hashedValue);
        }

        static async Task<string> computeMDC(byte[] byte_array)
        {

            byte[] hashedValue = md5.ComputeHash(byte_array);
            return "The corresponding MDC hash value for the byte array " + BitConverter.ToString(byte_array) + " is: " + BitConverter.ToString(hashedValue);
        }

        static async Task Main(string[] args)
        {
            //Console.WriteLine("Hello World!");
            // https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/async/
            
            var t1 = computeMDC("Lorem ipsum dolor sit amet", "string"); // for string
            var t2 = computeMDC("file1.txt", "file"); // for file content

            byte[] byte_array = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 }; // for byte array
            var t3 = computeMDC(byte_array);

            var tasks = new List<Task<string>> { t1, t2, t3 };
            while (tasks.Count > 0)
            {
                Task<string> finished = await Task.WhenAny(tasks);
                Console.WriteLine(finished.Result);
                tasks.Remove(finished);
            }

        }

    }
}
