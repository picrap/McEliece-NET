using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece;
using VTDev.Libraries.CEXEngine.Tools;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto;
using VTDev.Libraries.CEXEngine.Crypto.Prng;

namespace Test.Tests
{
    /// <summary>
    /// Test the validity of the CCA2 Encryption implementation
    /// </summary>
    public class McElieceEncryptionTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the CCA2 Encryption implementations";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! Encryption tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// Tests the validity of the CCA2 Encryption implementations
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                //TestKey();
                TestEncrypt();
                OnProgress(new TestEventArgs("Passed CCA2 encryption tests"));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private Methods
        private void TestKey()
        {
            MPKCParameters encParams = new MPKCParameters(11, 40, McElieceCiphers.Fujisaki);
            MPKCKeyGenerator keyGen = new MPKCKeyGenerator(encParams);
            IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
            byte[] enc, dec, data;

            // encrypt an array
            using (MPKCEncrypt cipher = new MPKCEncrypt(encParams))
            {
                cipher.Initialize(true, new MPKCKeyPair(keyPair.PublicKey));
                data = new byte[66];//cipher.MaxPlainText - 1
                new CSPRng().GetBytes(data);
                enc = cipher.Encrypt(data);
            }
            
            // decrypt the cipher text
            using (MPKCEncrypt cipher = new MPKCEncrypt(encParams))
            {
                cipher.Initialize(false, new MPKCKeyPair(keyPair.PrivateKey));
                dec = cipher.Decrypt(enc);
            }

            if (!Compare.AreEqual(dec, data))
                throw new Exception("TestKey test: decryption failure!");
            OnProgress(new TestEventArgs("Passed sub-key test"));
        }

        private void TestEncrypt()
        {
            MPKCParameters mpar = new MPKCParameters(11, 40, McElieceCiphers.Fujisaki);
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] enc;

            // Fujisaki
            using (MPKCEncrypt mpe = new MPKCEncrypt(mpar))
            {
                mpe.Initialize(true, akp);

                int sz = mpe.MaxPlainText - 1;
                byte[] data = new byte[sz];
                new CSPRng().GetBytes(data);

                enc = mpe.Encrypt(data);

                mpe.Initialize(false, akp);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
                OnProgress(new TestEventArgs("Passed Fujisaki encryption test"));
            }

            // KobaraLmai
            using (MPKCEncrypt mpe = new MPKCEncrypt(mpar))
            {
                mpar = new MPKCParameters(11, 40, McElieceCiphers.KobaraImai);
                mpe.Initialize(true, akp);

                int sz = mpe.MaxPlainText - 1;
                byte[] data = new byte[sz];
                new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPRng().GetBytes(data);

                enc = mpe.Encrypt(data);

                mpe.Initialize(false, akp);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
                OnProgress(new TestEventArgs("Passed KobaraImai encryption test"));
            }

            // Pointcheval
            using (MPKCEncrypt mpe = new MPKCEncrypt(mpar))
            {
                mpar = new MPKCParameters(11, 40, McElieceCiphers.Pointcheval);
                mpe.Initialize(true, akp);

                int sz = mpe.MaxPlainText - 1;
                byte[] data = new byte[sz];
                new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPRng().GetBytes(data);

                enc = mpe.Encrypt(data);

                mpe.Initialize(false, akp);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
                OnProgress(new TestEventArgs("Passed Pointcheval encryption test"));
            }
        }
        #endregion
    }
}
