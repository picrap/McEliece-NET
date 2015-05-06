﻿using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece;
using VTDev.Libraries.CEXEngine.Tools;
using System.IO;

namespace Test.Tests
{
    /// <summary>
    /// Test the validity of the EncryptionKey implementation
    /// </summary>
    public class McElieceKeyTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the EncryptionKey implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! EncryptionKey tests have executed succesfully.";
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
        /// Tests the validity of the EncryptionKey implementation
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                TestEncode();
                OnProgress(new TestEventArgs("Passed encryption key comparison tests"));

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
        private void TestEncode()
        {
            MPKCParameters mpar = new MPKCParameters(11, 40);
            MPKCKeyGenerator mkgen = new MPKCKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();

            MPKCPublicKey pub = (MPKCPublicKey)akp.PublicKey;
            byte[] enc = pub.ToBytes();
            using (MPKCPublicKey pub2 = MPKCPublicKey.Read(enc))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed public key serialization"));

            MemoryStream pubstr = pub.ToStream();
            using (MPKCPublicKey pub2 = MPKCPublicKey.Read(pubstr))
            {
                if (!pub.Equals(pub2))
                    throw new Exception("EncryptionKey: public key comparison test failed!");
            }
            pubstr.Dispose();
            OnProgress(new TestEventArgs("Passed public key stream test"));

            MPKCPrivateKey pri = (MPKCPrivateKey)akp.PrivateKey;
            enc = pri.ToBytes();
            using (MPKCPrivateKey pri2 = MPKCPrivateKey.Read(enc))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
            }
            OnProgress(new TestEventArgs("Passed private key serialization"));

            MemoryStream pristr = pri.ToStream();
            using (MPKCPrivateKey pri2 = MPKCPrivateKey.Read(pristr))
            {
                if (!pri.Equals(pri2))
                    throw new Exception("EncryptionKey: private key comparison test failed!");
            }
            pristr.Dispose();
            OnProgress(new TestEventArgs("Passed private key stream test"));

            using (MPKCEncrypt mpe = new MPKCEncrypt(mpar))
            {
                mpe.Initialize(true, akp);

                int sz = mpe.MaxPlainText - 1;
                byte[] data = new byte[sz];
                new VTDev.Libraries.CEXEngine.Crypto.Prng.CSPRng().GetBytes(data);

                enc = mpe.Encrypt(data);

                mpe.Initialize(false, akp);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("EncryptionKey: decryption failure!");
                OnProgress(new TestEventArgs("Passed encryption test"));
            }

            pri.Dispose();
            pub.Dispose();
        }
        #endregion
    }
}
