﻿#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Tools;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece
{
    /// <summary>
    /// An MPKCS One Time Sign (OTS) message sign and verify implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of using the signing and verifying an array:</description>
    /// <code>
    /// MPKCParameters encParams = new MPKCParameters(10, 50);
    /// MPKCKeyGenerator keyGen = new MPKCKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// byte[] code;
    /// byte[] data = new byte[100];
    ///
    /// // get the message code for an array of bytes
    /// using (MPKCSign signer = new MPKCSign(encParams))
    /// {
    ///     signer.Initialize(keyPair);
    ///     code = signer.Sign(data, 0, data.Length);
    /// }
    ///
    /// // test the message for validity
    /// using (MPKCSign signer = new MPKCSign(encParams))
    /// {
    ///     signer.Initialize(keyPair);
    ///     bool valid = signer.Verify(data, 0, data.Length, code);
    /// }
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/01/23" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.McElieceCiphers">VTDev.Libraries.CEXEngine.Crypto McElieceCiphers Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.MPKCPublicKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece MPKCPublicKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.MPKCPrivateKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece MPKCPrivateKey Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKeyPair Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces IAsymmetricKey Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest">VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest Interface</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <list type="bullet">
    /// <item><description>Signing is intended as a one time only key implementation (OTS); keys should never be re-used.</description></item>
    /// <item><description>Uses the McEliece CCA2 variants; Fujisaki, KobriImai, or PointCheval ciphers.</description></item>
    /// <item><description>Digests can be any of the implemented digests; Blake, Keccak, SHA-2 or Skein.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Based on the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> version.</description></item>
    /// </list> 
    /// </remarks>
    public class MPKCSign : IDisposable
    {
        #region Fields
        private IMPKCCiphers _asyCipher;
        private IDigest _dgtEngine;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private IAsymmetricKeyPair _keyPair;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        public int MaxPlainText
        {
            get 
            { 
                if (!_isInitialized)
                    throw new MPKCException("The signer has not been initialized!");

                if (_keyPair.PublicKey != null)
                    return ((MPKCPublicKey)_keyPair.PublicKey).K >> 3; 
                else
                    return ((MPKCPrivateKey)_keyPair.PrivateKey).K >> 3; 
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The McEliece cipher used to encrypt the hash</param>
        /// <param name="Digest">The type of digest engine used</param>
        public MPKCSign(MPKCParameters CipherParams, Digests Digest = Digests.SHA512)
        {
            _dgtEngine = GetDigest(CipherParams.Digest);
            _asyCipher = GetEngine(CipherParams);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCSign()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the cipher
        /// </summary>
        /// 
        /// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the McEliece public or private key</param>
        public void Initialize(IAsymmetricKeyPair KeyPair)
        {
            if (!(KeyPair is MPKCKeyPair))
                throw new MPKCException("The key pair is not a valid McEliece key pair!");

            Reset();
            _keyPair = KeyPair;
            _isInitialized = true;
        }

        /// <summary>
        /// Reset the underlying digest engine
        /// </summary>
        public void Reset()
        {
            _dgtEngine.Reset();
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The stream contining the data</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        public byte[] Sign(Stream InputStream)
        {
            if (!_isInitialized)
                throw new MPKCException("The signer has not been initialized!");
            if (_keyPair.PublicKey == null)
                throw new MPKCException("The public key is invalid!");
            if (!(_keyPair.PublicKey is MPKCPublicKey))
                throw new MPKCException("The public key is invalid!");

            _asyCipher.Initialize(true, _keyPair);

            if (_asyCipher.MaxPlainText < _dgtEngine.DigestSize)
                throw new MPKCException(String.Format("The key size is too small; key supports encrypting up to {0} bytes!", _asyCipher.MaxPlainText));

            byte[] hash = Compute(InputStream);

            return _asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Get the signing code for a stream
        /// </summary>
        /// 
        /// <param name="Input">The byte array contining the data</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The encrypted hash code</returns>
        public byte[] Sign(byte[] Input, int Offset, int Length)
        {
            if (Input.Length - Offset < Length)
                throw new MPKCException("The input array is too short!");
            if (!_isInitialized)
                throw new MPKCException("The signer has not been initialized!");
            if (_keyPair.PublicKey == null)
                throw new MPKCException("The public key is invalid!");
            if (!(_keyPair.PublicKey is MPKCPublicKey))
                throw new MPKCException("The public key is invalid!");

            _asyCipher.Initialize(true, _keyPair);

            if (_asyCipher.MaxPlainText < _dgtEngine.DigestSize)
                throw new MPKCException(String.Format("The key size is too small; key supports encrypting up to {0} bytes!", _asyCipher.MaxPlainText));

            byte[] hash = Compute(Input, Offset, Length);

            return _asyCipher.Encrypt(hash);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="InputStream">The stream containing the data to test</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        public bool Verify(Stream InputStream, byte[] Code)
        {
            if (!_isInitialized)
                throw new MPKCException("The signer has not been initialized!");
            if (_keyPair.PrivateKey == null)
                throw new MPKCException("The private key is invalid!");
            if (!(_keyPair.PrivateKey is MPKCPrivateKey))
                throw new MPKCException("The private key is invalid!");

            _asyCipher.Initialize(false, _keyPair);
            byte[] chksum = _asyCipher.Decrypt(Code);
            byte[] hash = Compute(InputStream);

            return Compare.AreEqual(hash, chksum);
        }

        /// <summary>
        /// Test the hashed value of a stream against the decrypted code
        /// </summary>
        /// 
        /// <param name="Input">The stream containing the data to test</param>
        /// <param name="Offset">The starting offset within the Input array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// <param name="Code">The encrypted hash code</param>
        /// 
        /// <returns>Returns <c>true</c> if the codes match</returns>
        public bool Verify(byte[] Input, int Offset, int Length, byte[] Code)
        {
            if (Input.Length - Offset < Length)
                throw new MPKCException("The input array is too short!");
            if (!_isInitialized)
                throw new MPKCException("The signer has not been initialized!");
            if (_keyPair.PrivateKey == null)
                throw new MPKCException("The private key is invalid!");
            if (!(_keyPair.PrivateKey is MPKCPrivateKey))
                throw new MPKCException("The private key is invalid!");

            _asyCipher.Initialize(false, _keyPair);
            byte[] chksum = _asyCipher.Decrypt(Code);
            byte[] hash = Compute(Input, Offset, Length);

            return Compare.AreEqual(hash, chksum);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Compute the hash from a stream
        /// </summary>
        /// 
        /// <param name="InputStream">The input stream</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(Stream InputStream)
        {
            int length = (int)(InputStream.Length - InputStream.Position);
            int blockSize = _dgtEngine.BlockSize < length ? length : _dgtEngine.BlockSize;
            int bytesRead = 0;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                bytesRead = InputStream.Read(buffer, 0, blockSize);
                _dgtEngine.BlockUpdate(buffer, 0, bytesRead);
                bytesTotal += bytesRead;
            }

            // last block
            if (bytesTotal < length)
            {
                buffer = new byte[length - bytesTotal];
                bytesRead = InputStream.Read(buffer, 0, buffer.Length);
                _dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
                bytesTotal += buffer.Length;
            }

            byte[] hash = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Compute the hash from a byte array
        /// </summary>
        /// 
        /// <param name="Input">The data byte array</param>
        /// <param name="Offset">The starting offset within the array</param>
        /// <param name="Length">The number of bytes to process</param>
        /// 
        /// <returns>The hash value</returns>
        private byte[] Compute(byte[] Input, int Offset, int Length)
        {
            if (Length < Input.Length - Offset)
                throw new ArgumentOutOfRangeException();

            int blockSize = _dgtEngine.BlockSize < Length ? Length : _dgtEngine.BlockSize;
            byte[] buffer = new byte[blockSize];
            int maxBlocks = Length / blockSize;
            int bytesTotal = 0;

            for (int i = 0; i < maxBlocks; i++)
            {
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, blockSize);
                _dgtEngine.BlockUpdate(buffer, 0, blockSize);
                bytesTotal += blockSize;
            }

            // last block
            if (bytesTotal < Length)
            {
                buffer = new byte[Length - bytesTotal];
                Array.Copy(Input, Offset + bytesTotal, buffer, 0, Math.Min(buffer.Length, Input.Length - bytesTotal));
                _dgtEngine.BlockUpdate(buffer, 0, buffer.Length);
            }

            byte[] hash = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="Engine">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests Engine)
        {
            switch (Engine)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                default:
                    return new SHA512();
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="CipherParams">The engine type</param>
        /// 
        /// <returns>An initialized cipher</returns>
        private IMPKCCiphers GetEngine(MPKCParameters CipherParams)
        {
            switch (CipherParams.Engine)
            {
                case McElieceCiphers.KobaraImai:
                    return new KobaraImaiCipher(CipherParams);
                case McElieceCiphers.Pointcheval:
                    return new PointchevalCipher(CipherParams);
                default:
                    return new FujisakiCipher(CipherParams);
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_dgtEngine != null)
                    {
                        _dgtEngine.Dispose();
                        _dgtEngine = null;
                    }
                    if (_asyCipher != null)
                    {
                        _asyCipher.Dispose();
                        _asyCipher = null;
                    }
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
