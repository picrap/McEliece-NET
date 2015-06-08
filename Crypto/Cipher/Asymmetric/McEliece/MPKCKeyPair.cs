#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece
{
    /// <summary>
    /// An McEliece Key-Pair container
    /// </summary>
    public sealed class MPKCKeyPair : IAsymmetricKeyPair
    {
        #region Fields
        private IAsymmetricKey _publicKey;
        private IAsymmetricKey _privateKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the public key parameters
        /// </summary>
        public IAsymmetricKey PublicKey
        {
            get { return _publicKey; }
        }

        /// <summary>
        /// Get: Returns the private key parameters
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return _privateKey; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="PublicKey">The public key</param>
        /// <param name="PrivateKey">The corresponding private key</param>
        public MPKCKeyPair(IAsymmetricKey PublicKey, IAsymmetricKey PrivateKey)
        {
            _publicKey = PublicKey;
            _privateKey = PrivateKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Key">The public or private key</param>
        public MPKCKeyPair(IAsymmetricKey Key)
        {
            if (Key is MPKCPublicKey)
                _publicKey = Key;
            else if (Key is MPKCPrivateKey)
                _privateKey = Key;
            else
                throw new MPKCException("Not a valid McEliece key!");
        }

        private MPKCKeyPair()
        {
        }
        #endregion
    }
}
