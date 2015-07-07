using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Projects.CEX.Test.Tests.Asymmetric.McEliece;
using System.Diagnostics;
using VTDev.Libraries.CEXEngine.Crypto.Prng;

namespace Test
{
    static class Program
    {
        const int CYCLE_COUNT = 10;
        const string CON_TITLE = "MPKC> ";

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
            Console.WriteLine("* Release:   v1.1                            *");
            Console.WriteLine("* Date:      July 7, 2015                    *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");
            Console.WriteLine("COMPILE as Any CPU | Release mode, RUN the .exe for real timings");
            Console.WriteLine("");

            if (Debugger.IsAttached)
            {
                Console.WriteLine("You are running in Debug mode! Compiled times will be much faster..");
                Console.WriteLine("");
            }

            Console.WriteLine(CON_TITLE + "Run Validation Tests? Press 'Y' to run, any other key to skip..");
            ConsoleKeyInfo keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
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
                Console.WriteLine("Validation Tests Completed!");
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Speed Tests? Press 'Y' to run, any other key to skip..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                EncryptionSpeed(CYCLE_COUNT);
                DecryptionSpeed(CYCLE_COUNT);
                KeyGenSpeed(CYCLE_COUNT);
                Console.WriteLine("Speed Tests Completed!");
                Console.WriteLine("");
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Looping Full-Cycle Tests? Press 'Y' to run, all other keys close..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                Console.WriteLine("");
                Console.WriteLine("******Looping: Key Generation/Encryption/Decryption and Verify Test******");
                Console.WriteLine(string.Format("Testing {0} Full Cycles, throws on all failures..", CYCLE_COUNT));
                try
                {
                    CycleTest(CYCLE_COUNT);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("!Loop test failed! " + ex.Message);
                }
                Console.WriteLine("");
                Console.WriteLine(CON_TITLE + "All tests have completed, press any key to close..");
                Console.ReadKey();
            }
            else
            {
                Environment.Exit(0);
            }
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

        #region Timing Tests
        static void CycleTest(int Iterations)
        {
            Stopwatch runTimer = new Stopwatch();
            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                FullCycle();
            runTimer.Stop();

            double elapsed = runTimer.Elapsed.TotalMilliseconds;
            Console.WriteLine(string.Format("{0} cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Average cycle time: {0} ms", elapsed / Iterations));
            Console.WriteLine("");
        }

        static void DecryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Decryption Test: Testing {0} Iterations******", Iterations));

            Console.WriteLine("Test decryption times using the MPKCFM11T40S256 parameter set.");
            double elapsed = Decrypt(Iterations, MPKCParamSets.MPKCFM11T40S256);
            Console.WriteLine(string.Format("{0} decryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Decryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Console.WriteLine("Test decryption times using the MPKCFM11T48S256 parameter set.");
            elapsed = Decrypt(Iterations, MPKCParamSets.MPKCFM11T48S256);
            Console.WriteLine(string.Format("{0} decryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Decryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static void EncryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Encryption Test: Testing {0} Iterations******", Iterations));

            Console.WriteLine("Test encryption times using the MPKCFM11T40S256 parameter set.");
            double elapsed = Encrypt(Iterations, MPKCParamSets.MPKCFM11T40S256);
            Console.WriteLine(string.Format("{0} encryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Encryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Console.WriteLine("Test encryption times using the MPKCFM11T48S256 parameter set.");
            elapsed = Encrypt(Iterations, MPKCParamSets.MPKCFM11T48S256);
            Console.WriteLine(string.Format("{0} encryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Encryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static void FullCycle()
        {
            MPKCParameters mpar = MPKCParamSets.MPKCFM11T40S256; //APR2011743FAST
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] enc;

            using (MPKCEncrypt mpe = new MPKCEncrypt(mpar))
            {
                mpe.Initialize(akp.PublicKey);

                byte[] data = new byte[mpe.MaxPlainText];
                enc = mpe.Encrypt(data);
                mpe.Initialize(akp.PrivateKey);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
            }
        }

        static void KeyGenSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("Key creation average time over {0} passes:", Iterations));
            Stopwatch runTimer = new Stopwatch();
            double elapsed;

            elapsed = KeyGenerator(Iterations, MPKCParamSets.MPKCFM11T40S256);
            Console.WriteLine(string.Format("MPKCFM11T40S256: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Creation Rate is {0} keys per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            elapsed = KeyGenerator(Iterations, MPKCParamSets.MPKCFM11T48S256);
            Console.WriteLine(string.Format("MPKCFM11T48S256: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Creation Rate is {0} keys per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Iterations = 4;
            Console.WriteLine(string.Format("Testing each key with {0} passes:", Iterations));
            Console.WriteLine("");

            foreach (int p in Enum.GetValues(typeof(MPKCParamSets.MPKCParamNames)))
            {
                MPKCParameters param = MPKCParamSets.FromName((MPKCParamSets.MPKCParamNames)p);
                elapsed = KeyGenerator(Iterations, param);
                Console.WriteLine(string.Format(Enum.GetName(typeof(MPKCParamSets.MPKCParamNames), p) + ": avg. {0} ms", elapsed / Iterations, Iterations));
                Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
                Console.WriteLine("");
            }

            Console.WriteLine("");
        }

        static double KeyGenerator(int Iterations, MPKCParameters Param)
        {
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(Param);
            IAsymmetricKeyPair akp;
            Stopwatch runTimer = new Stopwatch();

            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                akp = mkgen.GenerateKeyPair();
            runTimer.Stop();

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double Decrypt(int Iterations, MPKCParameters Param)
        {
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(64);
            byte[] rtext = new byte[64];
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (MPKCEncrypt mpe = new MPKCEncrypt(Param))
            {
                mpe.Initialize(akp.PublicKey);
                ctext = mpe.Encrypt(ptext);
                mpe.Initialize(akp.PrivateKey);

                runTimer.Start();
                for (int i = 0; i < Iterations; i++)
                    rtext = mpe.Decrypt(ctext);
                runTimer.Stop();
            }

            //if (!Compare.AreEqual(ptext, rtext))
            //    throw new Exception("Encryption test: decryption failure!");

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double Encrypt(int Iterations, MPKCParameters Param)
        {
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(64);
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (MPKCEncrypt mpe = new MPKCEncrypt(Param))
            {
                mpe.Initialize(akp.PublicKey);

                runTimer.Start();
                for (int i = 0; i < Iterations; i++)
                    ctext = mpe.Encrypt(ptext);
                runTimer.Stop();
            }

            return runTimer.Elapsed.TotalMilliseconds;
        }
        #endregion
    }
}
