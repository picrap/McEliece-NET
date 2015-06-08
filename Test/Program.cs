using System;
using Test.Tests;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece;
using VTDev.Libraries.CEXEngine.Tools;

namespace Test
{
    static class Program
    {
        #region Main
        static void Main(string[] args)
        {
            ConsoleUtils.SizeConsole(80, 60);
            ConsoleUtils.CenterConsole();
            Console.Title = "McEliece Sharp Test Suite";

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
        #endregion

        #region Loop Test
        static void CycleTest()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM12T41S256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] enc;

            // Fujisaki
            using (MPKCEncrypt mpe = new MPKCEncrypt(mpar))
            {
                mpe.Initialize(true, akp);

                int sz = mpe.MaxPlainText;
                byte[] data = new byte[sz];
                enc = mpe.Encrypt(data);
                mpe.Initialize(false, akp);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
            }/**/
        }

        static void EncryptionSpeed(int Iterations = 100)
        {
            Console.WriteLine(string.Format("******Looping Encryption Test: Testing {0} Iterations******", Iterations));
            Console.WriteLine("Test cycle generates keys, encrypts, decrypts and verifies success.");
            Console.WriteLine("Test throws on all errors.");
            Console.WriteLine("");

            for (int i = 0; i < Iterations; i++)
            {
                // gen keys, encrypt, decrypt and verify
                string tm = TimeAction(CycleTest, 1);
                Console.WriteLine(string.Format("Passed Iteration {0} in {1} ms.", i + 1, tm));
            }

            Console.WriteLine("");
            Console.WriteLine("Completed! Press any key to continuue..");
            Console.ReadKey();
        }
        #endregion

        #region Timing Test
        static void KeyGenSpeed(int Iterations = 1)
        {
            Console.WriteLine(string.Format("M/T/Security: Key creation average time over {0} passes:", Iterations));
            Console.WriteLine("11/40/95:  " + TimeAction(new Action(TM1140), Iterations));
            Console.WriteLine("11/48/98:  " + TimeAction(new Action(TM1148), Iterations));
            Console.WriteLine("12/31/108: " + TimeAction(new Action(TM1231), Iterations));
            Console.WriteLine("12/41/129: " + TimeAction(new Action(TM1241), Iterations));
            Console.WriteLine("12/48/138: " + TimeAction(new Action(TM1248), Iterations));
            Console.WriteLine("12/54/133: " + TimeAction(new Action(TM1254), Iterations));
            Console.WriteLine("13/29/128: " + TimeAction(new Action(TM1329), Iterations));
            Console.WriteLine("13/44/136: " + TimeAction(new Action(TM1344), Iterations));
            Console.WriteLine("14/24/115: " + TimeAction(new Action(TM1424), Iterations));
            Console.WriteLine("");

            Console.ReadKey();
        }

        private static string TimeAction(Action Test, int Iterations = 1)
        {
            // output results to a label to test compiled times..
            string ft = @"m\:ss\.ff";
            System.Diagnostics.Stopwatch runTimer = new System.Diagnostics.Stopwatch();

            runTimer.Start();

            for (int i = 0; i < Iterations; i++)
                Test();

            runTimer.Stop();

            return TimeSpan.FromMilliseconds(runTimer.Elapsed.TotalMilliseconds / Iterations).ToString(ft);
        }

        static void TM1140()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM11T40S256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1148()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM11T48S256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1231()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM12T31S256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1241()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM12T41S256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1248()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM12T48S256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1254()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM12T54K256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1329()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM13T29S256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1344()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM13T44K256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }

        static void TM1424()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM14T24K256;
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
        }
        #endregion
    }
}
