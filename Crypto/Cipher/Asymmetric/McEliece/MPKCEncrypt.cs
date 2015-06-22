#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.MPKCCiphers;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece
{
    /// <summary>
    /// An McEliece CCA2 cipher implementation
    /// </summary>
    /// 
    /// <example>
    /// <description>Example of encrypting and decrypting an array:</description>
    /// <code>
    /// MPKCParameters encParams = new MPKCParameters(11, 40, McElieceCiphers.Fujisaki);
    /// MPKCKeyGenerator keyGen = new MPKCKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// 
    /// byte[] data = new byte[100];
    /// byte[] enc, dec;
    /// 
    /// // encrypt an array
    /// using (MPKCEncrypt cipher = new MPKCEncrypt(encParams))
    /// {
    ///     cipher.Initialize(true, new MPKCKeyPair(keyPair.PublicKey));
    ///     enc = cipher.Encrypt(data);
    /// }
    /// 
    /// // decrypt the cipher text
    /// using (MPKCEncrypt cipher = new MPKCEncrypt(encParams))
    /// {
    ///     cipher.Initialize(false, new MPKCKeyPair(keyPair.PrivateKey));
    ///     dec = cipher.Decrypt(enc);
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
    /// <item><description>Uses the McEliece CCA2 variants; Fujisaki, KobriImai, or PointCheval ciphers.</description></item>
    /// <item><description>Use the MaxPlainText property to get max input size post initialization.</description></item>
    /// <item><description>The MaxCipherText property gives the max allowable ciphertext size post initialization.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> versions McEliece implementation.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCEncrypt : IAsymmetricCipher
    {
        #region Fields
        private IMPKCCiphers _encEngine;
        private bool _isDisposed = false;
        private bool _isInitialized = false;
        private int _maxPlainText;
        private int _maxCipherText;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The maximum number of bytes the cipher can encrypt
        /// </summary>
        /// 
        /// <exception cref="MPKCException">Thrown if the cipher is not initialized</exception>
        public int MaxCipherText
        {
            get 
            {
                if (_maxCipherText == 0 || !_isInitialized)
                    throw new MPKCException("MPKCEncrypt:MaxCipherText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return _maxCipherText; 
            }
        }

        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        /// 
        /// <exception cref="MPKCException">Thrown if the cipher is not initialized</exception>
        public int MaxPlainText
        {
            get 
            {
                if (_maxPlainText == 0 || !_isInitialized)
                    throw new MPKCException("MPKCEncrypt:MaxPlainText", "The cipher must be initialized before size can be calculated!", new InvalidOperationException());

                return _maxPlainText; 
            }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The cipher engine</param>
        public MPKCEncrypt(MPKCParameters CipherParams)
        {
            _encEngine = GetEngine(CipherParams);
        }

        private MPKCEncrypt()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCEncrypt()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt a cipher text
        /// </summary>
        /// 
        /// <param name="Input">The cipher text</param>
        /// 
        /// <returns>The plain text</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if the cipher is not initialized</exception>
        public byte[] Decrypt(byte[] Input)
        {
            if (!_isInitialized)
                throw new MPKCException("MPKCEncrypt:Decrypt", "The cipher has not been initialized!", new InvalidOperationException());

            return _encEngine.Decrypt(Input);
        }

        /// <summary>
        /// Encrypt a plain text message
        /// </summary>
        /// 
        /// <param name="Input">The plain text</param>
        /// 
        /// <returns>The cipher text</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if the cipher is not initialized, or the input text is invalid</exception>
        public byte[] Encrypt(byte[] Input)
        {
            if (!_isInitialized)
                throw new MPKCException("MPKCEncrypt:Encrypt", "The cipher has not been initialized!", new InvalidOperationException());
            if (Input.Length > _maxPlainText)
                throw new MPKCException("MPKCEncrypt:Encrypt", "The input text is too long!", new ArgumentException());

            return _encEngine.Encrypt(Input);
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <param name="Key">The key</param>
        /// 
        /// <returns>The size of the key</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if the cipher is not initialized</exception>
        public int GetKeySize(IAsymmetricKey Key)
        {
            if (!_isInitialized)
                throw new MPKCException("MPKCEncrypt:GetKeySize", "The cipher has not been initialized!", new InvalidOperationException());

            if (Key is MPKCPublicKey)
                return ((MPKCPublicKey)Key).N;
            if (Key is MPKCPrivateKey)
                return ((MPKCPrivateKey)Key).N;

            throw new MPKCException("MPKCEncrypt:GetKeySize", "Unsupported key type!", new ArgumentException());
        }

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="MPKCPublicKey"/> for encryption, or a <see cref="MPKCPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="Encryption">When true cipher is for encryption, if false, decryption</param>
        /// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the McEliece public or private key</param>
        /// 
        /// <exception cref="MPKCException">Thrown if the cipher is not initialized or the key is invalid</exception>
        public void Initialize(bool Encryption, IAsymmetricKeyPair KeyPair)
        {
            if (!(KeyPair is MPKCKeyPair))
                throw new MPKCException("MPKCEncrypt:Initialize", "Not a valid McEliece key pair!", new InvalidOperationException());

            // init implementation engine
            _encEngine.Initialize(Encryption, KeyPair);

            // get the sizes
            if (Encryption)
            {
                if (KeyPair.PublicKey == null)
                    throw new MPKCException("MPKCEncrypt:Initialize", "Encryption requires a public key!", new InvalidOperationException());
                if (!(KeyPair.PublicKey is MPKCPublicKey))
                    throw new MPKCException("MPKCEncrypt:Initialize", "The public key is invalid!", new ArgumentException());

                MPKCPublicKey pub = (MPKCPublicKey)KeyPair.PublicKey;
                _maxCipherText = pub.N >> 3;
                _maxPlainText = pub.K >> 3;
            }
            else
            {
                if (KeyPair.PrivateKey == null)
                    throw new MPKCException("MPKCEncrypt:Initialize", "Decryption requires a private key!", new InvalidOperationException());
                if (!(KeyPair.PrivateKey is MPKCPrivateKey))
                    throw new MPKCException("MPKCEncrypt:Initialize", "The private key is invalid!", new ArgumentException());

                MPKCPrivateKey pri = (MPKCPrivateKey)KeyPair.PrivateKey;
                _maxPlainText = pri.K >> 3;
                _maxCipherText = pri.N >> 3;
            }

            _isInitialized = true;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="CipherParams">The cipher parameters</param>
        /// 
        /// <returns>An initialized cipher</returns>
        private IMPKCCiphers GetEngine(MPKCParameters CipherParams)
        {
            switch (CipherParams.CCA2Engine)
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
                    if (_encEngine != null)
                    {
                        _encEngine.Dispose();
                        _encEngine = null;
                    }
                    _maxPlainText = 0;
                    _maxCipherText = 0;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
