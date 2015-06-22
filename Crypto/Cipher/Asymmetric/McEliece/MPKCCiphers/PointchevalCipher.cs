#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Generator;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.MPKCCiphers
{
    /// <summary>
    /// This class implements the Pointcheval conversion of the McEliecePKCS.
    /// <para>Pointcheval presents a generic technique to make a CCA2-secure cryptosystem 
    /// from any partially trapdoor one-way function in the random oracle model.</para>
    /// </summary>
    internal class PointchevalCipher : IMPKCCiphers, IDisposable
    {
        #region Constants
        /// <summary>
        /// The OID of the algorithm
        /// </summary>
        public static readonly byte[] OID = System.Text.Encoding.ASCII.GetBytes("1.3.6.1.4.1.8301.3.1.3.4.2.2");
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private bool _isEncryption = false;
        private IAsymmetricKeyPair _keyPair;
        private int _maxPlainText;
        private IDigest _dgtEngine;
        private IRandom _secRnd;
        private int _K; 
        private int _N;
        private int _T;
        private MPKCParameters _cipherParams;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The maximum number of bytes the cipher can decrypt
        /// </summary>
        public int MaxPlainText
        {
            get { return _maxPlainText; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher parameters</param>
        public PointchevalCipher(MPKCParameters Parameters)
        {
            _cipherParams = Parameters;
            _dgtEngine = GetDigest(Parameters.Digest);
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~PointchevalCipher()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        public byte[] Decrypt(byte[] Input)
        {
            int c1Len = (_N + 7) >> 3;
            int c2Len = Input.Length - c1Len;
            // split cipher text (c1||c2)
            byte[][] c1c2 = ByteUtils.Split(Input, c1Len);
            byte[] c1 = c1c2[0];
            byte[] c2 = c1c2[1];

            // decrypt c1 ...
            GF2Vector c1Vec = GF2Vector.OS2VP(_N, c1);
            GF2Vector[] c1Dec = CCA2Primitives.Decrypt((MPKCPrivateKey)_keyPair.PrivateKey, c1Vec);
            byte[] rPrimeBytes = c1Dec[0].GetEncoded();
            // ... and obtain error vector z
            GF2Vector z = c1Dec[1];

            byte[] mrBytes;
            // get PRNG object
            using (KDF2Drbg sr0 = new KDF2Drbg(GetDigest(_cipherParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rPrimeBytes);
                // generate random sequence
                mrBytes = new byte[c2Len];
                sr0.Generate(mrBytes);
            }

            // XOR with c2 to obtain (m||r)
            for (int i = 0; i < c2Len; i++)
                mrBytes[i] ^= c2[i];

            // compute H(m||r)
            _dgtEngine.BlockUpdate(mrBytes, 0, mrBytes.Length);
            byte[] hmr = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hmr, 0);

            // compute Conv(H(m||r))
            c1Vec = CCA2Conversions.Encode(_N, _T, hmr);

            // check that Conv(H(m||r)) = z
            if (!c1Vec.Equals(z))
                throw new Exception("Bad Padding: Invalid ciphertext!");// Note: will throw (sometimes), but only on Pointcheval w/ small m/t?

            // split (m||r) to obtain m
            int kDiv8 = _K >> 3;
            byte[][] mr = ByteUtils.Split(mrBytes, c2Len - kDiv8);

            // return plain text m
            return mr[0];
        }

        public byte[] Encrypt(byte[] Input)
        {
            int kDiv8 = _K >> 3;
            // generate random r of length k div 8 bytes
            byte[] r = new byte[kDiv8];
            _secRnd.GetBytes(r);
            // generate random vector r' of length k bits
            GF2Vector rPrime = new GF2Vector(_K, _secRnd);
            // convert r' to byte array
            byte[] rPrimeBytes = rPrime.GetEncoded();
            // compute (input||r)
            byte[] mr = ByteUtils.Concatenate(Input, r);
            // compute H(input||r)
            _dgtEngine.BlockUpdate(mr, 0, mr.Length);
            byte[] hmr = new byte[_dgtEngine.DigestSize];
            _dgtEngine.DoFinal(hmr, 0);

            // convert H(input||r) to error vector z
            GF2Vector z = CCA2Conversions.Encode(_N, _T, hmr);

            // compute c1 = E(rPrime, z)
            byte[] c1 = CCA2Primitives.Encrypt((MPKCPublicKey)_keyPair.PublicKey, rPrime, z).GetEncoded();
            byte[] c2;
            // get PRNG object
            using (KDF2Drbg sr0 = new KDF2Drbg(GetDigest(_cipherParams.Digest)))
            {
                // seed PRNG with r'
                sr0.Initialize(rPrimeBytes);
                // generate random c2
                c2 = new byte[Input.Length + kDiv8];
                sr0.Generate(c2);
            }

            // XOR with input
            for (int i = 0; i < Input.Length; i++)
                c2[i] ^= Input[i];

            // XOR with r
            for (int i = 0; i < kDiv8; i++)
                c2[Input.Length + i] ^= r[i];

            // return (c1||c2)
            return ByteUtils.Concatenate(c1, c2);
        }

        /// <summary>
        /// Return the key size of the working key
        /// </summary>
        /// 
        /// <returns>The size of the key</returns>
        public int GetKeySize(IAsymmetricKey Key)
        {
            if (Key is MPKCPublicKey)
                return ((MPKCPublicKey)Key).N;
            if (Key is MPKCPrivateKey)
                return ((MPKCPrivateKey)Key).N;

            throw new ArgumentException("unsupported type");
        }

        /// <summary>
        /// Initialize the cipher.
        /// <para>Requires a <see cref="MPKCPublicKey"/> for encryption, or a <see cref="MPKCPrivateKey"/> for decryption</para>
        /// </summary>
        /// 
        /// <param name="Encryption">When true cipher is for encryption, if false, decryption</param>
        /// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the McEliece public or private key</param>
        public void Initialize(bool Encryption, IAsymmetricKeyPair KeyPair)
        {
            _isEncryption = Encryption;
            _keyPair = KeyPair;

            if (_isEncryption)
            {
                _secRnd = GetPrng(_cipherParams.RandomEngine);
                _N = ((MPKCPublicKey)KeyPair.PublicKey).N;
                _K = ((MPKCPublicKey)KeyPair.PublicKey).K;
                _T = ((MPKCPublicKey)KeyPair.PublicKey).T;
                _maxPlainText = (((MPKCPublicKey)KeyPair.PublicKey).K >> 3);
            }
            else
            {
                _N = ((MPKCPrivateKey)KeyPair.PrivateKey).N;
                _K = ((MPKCPrivateKey)KeyPair.PrivateKey).K;
                _T = ((MPKCPrivateKey)KeyPair.PrivateKey).T;
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="Digest">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests Digest)
        {
            switch (Digest)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.Keccak1024:
                    return new Keccak1024();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.SHA512:
                    return new SHA512();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                case Digests.Skein1024:
                    return new Skein1024();
                default:
                    throw new ArgumentException("The digest type is not supported!");
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="Prng">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs Prng)
        {
            switch (Prng)
            {
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.CSPRng:
                    return new CSPRng();
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    throw new ArgumentException("The Prng type is not supported!");
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
                    if (_secRnd != null)
                    {
                        _secRnd.Dispose();
                        _secRnd = null;
                    }
                    _K = 0;
                    _N = 0;
                    _T = 0;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
