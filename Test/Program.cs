using System;
using Test.Tests;

namespace Test
{
    static class Program
    {
        static void Main(string[] args)
        {
            // header
            Console.WriteLine("**********************************************");
            Console.WriteLine("* McEliece Encrypt in C# (McEliece Sharp)    *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.0                            *");
            Console.WriteLine("* Date:      May 4, 2015                     *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");

            // encrypt
            Console.WriteLine("******TESTING ENCRYPTION AND DECRYPTION******");
            RunTest(new McElieceEncryptionTest());
            Console.WriteLine("");/**/

            // serialization tests
            Console.WriteLine("******TESTING KEY SERIALIZATION******");
            RunTest(new McElieceKeyTest());
            Console.WriteLine("");/**/

            Console.WriteLine("******TESTING PARAMETERS******");
            RunTest(new McElieceParamTest());
            Console.WriteLine("");/**/

            // cca2 encryption
            Console.WriteLine("******TESTING SIGNING FUNCTIONS******");
            RunTest(new McElieceSignTest());
            Console.WriteLine("");/**/

            Console.WriteLine("Completed! Press any key to close..");
            Console.ReadKey();
        }

        private static void RunTest(ITest Test)
        {
            try
            {
                Test.Progress -= OnTestProgress;
                Test.Progress += new EventHandler<TestEventArgs>(OnTestProgress);
                Console.WriteLine(Test.Description);
                Console.WriteLine(Test.Test());
                Console.WriteLine();
            }
            catch (Exception Ex)
            {
                Console.WriteLine("An error has occured!");
                Console.WriteLine(Ex.Message);
                Console.WriteLine("");
                Console.WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");
                ConsoleKeyInfo keyInfo = Console.ReadKey();

                if (!keyInfo.Key.Equals(ConsoleKey.Y))
                    Environment.Exit(0);
                else
                    Console.WriteLine();
            }
        }

        private static void OnTestProgress(object sender, TestEventArgs e)
        {
            Console.WriteLine(e.Message);
        }
    }
}
