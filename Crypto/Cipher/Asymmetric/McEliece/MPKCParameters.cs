#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Exceptions;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece
{
    /// <summary>
    /// Creates, reads and writes parameter settings for MPKCEncrypt.
    /// <para>Predefined parameter sets are available and new ones can be created as well.
    /// These predefined settings are accessable through the <see cref="MPKCParamSets"/> class</para>
    /// <para>Digest size is limited to 256 bits; larger digest sizes are not required.</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Create a parameter set and write to stream:</description>
    /// <code>
    /// MemoryStream ks = new MemoryStream();
    /// using (MPKCParameters mp = new MPKCParameters(11, 40, McElieceCiphers.Fujisaki, Digests.SHA256))
    ///    mp.WriteTo(ks);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/01/23" version="1.0.1.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.MPKCEncrypt">VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece MPKCEncrypt Class</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prngs">VTDev.Libraries.CEXEngine.Crypto.McElieceCiphers Enumeration</seealso>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digests">VTDev.Libraries.CEXEngine.Crypto.Digests Enumeration</seealso>
    /// 
    /// <remarks>
    /// <description><h4>MPKC Parameter Description:</h4></description>
    /// <list type="table">
    /// <item><description>M - The degree of the finite field GF(2^m).</description></item>
    /// <item><description>T - The error correction capability of the code.</description></item>
    /// <item><description>Engine - The McEliece CCA2 cipher engine.</description></item>
    /// <item><description>Digest - The digest used by the cipher engine.</description></item>
    /// </list>
    /// 
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: Chapter 8<cite>McEliece Handbook of Applied Cryptography</cite>.</description></item>
    /// <item><description>Selecting Parameters for Secure McEliece-based Cryptosystems<cite>McEliece Parameters</cite>.</description></item>
    /// <item><description>Weak keys in the McEliece public-key cryptosystem<cite>McEliece Weak keys</cite>.</description></item>
    /// <item><description>McBits: fast constant-time code-based cryptography<cite>McEliece McBits</cite>.</description></item>
    /// </list>
    /// 
    /// <description><h4>Code Base Guides:</h4></description>
    /// <list type="table">
    /// <item><description>Inspired by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see> versions McEliece implementation.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCParameters : IAsymmetricParameters
    {
        #region Constants
        /// <summary>
        /// The default extension degree
        /// </summary>
        public const int DEFAULT_M = 11;

        /// <summary>
        /// The default error correcting capability
        /// </summary>
        public const int DEFAULT_T = 50;
        #endregion

        #region Fields
        private int _M;
        private int _T;
        private int _N;
        private byte[] _oId = new byte[3];
        private int _fieldPoly;
        private bool _isDisposed = false;
        private Digests _dgtEngine = Digests.SHA256;
        private Prngs _rndEngine = Prngs.CTRPrng;
        private McElieceCiphers _cca2Engine = McElieceCiphers.Pointcheval;
        #endregion

        #region Properties
        /// <summary>
        /// The digest engine used to power CCA2 variants
        /// </summary>
        /// 
        /// <exception cref="MPKCException">Thrown if an invalid digest is specified</exception>
        public Digests Digest
        {
            get { return _dgtEngine; }
            private set
            {
                if (value == Digests.Keccak1024 || value == Digests.Skein1024)
                    throw new MPKCException("MPKCParameters:Digest", "Only 512 and 256 bit Digests are supported!", new ArgumentException());

                _dgtEngine = value;
            }
        }

        /// <summary>
        /// The cipher engine used for encryption
        /// </summary>
        public McElieceCiphers CCA2Engine
        {
            get { return _cca2Engine; }
            private set { _cca2Engine = value; }
        }

        /// <summary>
        /// Returns the extension degree of the finite field GF(2^m)
        /// </summary>
        public int M
        {
            get { return _M; }
        }

        /// <summary>
        /// Returns the length of the code
        /// </summary>
        public int N
        {
            get { return _N; }
        }


        /// <summary>
        /// The cipher Prng
        /// </summary>
        public Prngs RandomEngine
        {
            get { return _rndEngine; }
            private set { _rndEngine = value; }
        }

        /// <summary>
        /// Get: Three b
        /// ytes that uniquely identify the parameter set
        /// </summary>
        /// 
        /// <exception cref="MPKCException">Thrown if an invalid OId is specified</exception>
        public byte[] OId
        {
            get { return _oId; }
            private set
            {
                if (value == null)
                    throw new MPKCException("MPKCParameters:OId", "Oid can not be null!", new ArgumentNullException());
                if (value.Length != 3)
                    throw new MPKCException("MPKCParameters:OId", "Oid must be 3 bytes in length!", new ArgumentException());

                _oId = value;
            }
        }

        /// <summary>
        /// Return the error correction capability of the code
        /// </summary>
        public int T
        {
            get { return _T; }
        }

        /// <summary>
        /// Returns the field polynomial
        /// </summary>
        public int FieldPolynomial
        {
            get { return _fieldPoly; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Set the default parameters: extension degree
        /// </summary>
        /// 
        /// <param name="OId">Three bytes that uniquely identify the parameter set</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The prng used by the cipher engine</param>
        public MPKCParameters(byte[] OId, McElieceCiphers CCA2Engine = McElieceCiphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng) :
            this(DEFAULT_M, DEFAULT_T, OId)
        {
            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;
        }


        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Keysize">The length of a Goppa code</param>
        /// <param name="OId">Three bytes that uniquely identify the parameter set</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="MPKCException">Thrown if <c>keysize &lt; 1</c></exception>
        public MPKCParameters(int Keysize, byte[] OId, McElieceCiphers CCA2Engine = McElieceCiphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (Keysize < 1)
                throw new MPKCException("MPKCParameters:Ctor", "The key size must be positive!", new ArgumentException());

            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;

            Array.Copy(OId, this.OId, Math.Min(OId.Length, 3));
            _M = 0;
            _N = 1;

            while (_N < Keysize)
            {
                _N <<= 1;
                _M++;
            }
            _T = _N >> 1;
            _T /= _M;

            _fieldPoly = PolynomialRingGF2.GetIrreduciblePolynomial(_M);
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="M">The degree of the finite field GF(2^m)</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="OId">Three bytes that uniquely identify the parameter set</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="MPKCException">Thrown if; <c>m &lt; 1</c>, <c>m &gt; 32</c>, <c>t &lt; 0</c> or <c>t &gt; n</c></exception>
        public MPKCParameters(int M, int T, byte[] OId, McElieceCiphers CCA2Engine = McElieceCiphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (M < 1)
                throw new MPKCException("MPKCParameters:Ctor", "M must be positive!", new ArgumentException());
            if (M > 32)
                throw new MPKCException("MPKCParameters:Ctor", "M is too large!", new ArgumentOutOfRangeException());

            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;

            Array.Copy(OId, this.OId, Math.Min(OId.Length, 3));
            _M = M;
            _N = 1 << M;

            if (T < 0)
                throw new MPKCException("MPKCParameters:Ctor", "T must be positive!", new ArgumentException());
            if (T > N)
                throw new MPKCException("MPKCParameters:Ctor", "T must be less than n = 2^m!", new ArgumentOutOfRangeException());

            _T = T;
            _fieldPoly = PolynomialRingGF2.GetIrreduciblePolynomial(M);
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="M">The degree of the finite field GF(2^m)</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="FieldPoly">The field polynomial</param>
        /// <param name="OId">Three bytes that uniquely identify the parameter set</param>
        /// <param name="CCA2Engine">The McEliece CCA2 cipher engine</param>
        /// <param name="Digest">The digest used by the cipher engine</param>
        /// <param name="Prng">The Prng used by the cipher</param>
        /// 
        /// <exception cref="MPKCException">Thrown if; <c>t &lt; 0</c>, <c>t &gt; n</c>, or <c>poly</c> is not an irreducible field polynomial</exception>
        public MPKCParameters(int M, int T, int FieldPoly, byte[] OId, McElieceCiphers CCA2Engine = McElieceCiphers.Fujisaki, Digests Digest = Digests.SHA256, Prngs Prng = Prngs.CTRPrng)
        {
            if (M < 1)
                throw new MPKCException("MPKCParameters:Ctor", "M must be positive!", new ArgumentException());
            if (M > 32)
                throw new MPKCException("MPKCParameters:Ctor", "M is too large!", new ArgumentOutOfRangeException());

            _M = M;
            this.Digest = Digest;
            this.CCA2Engine = CCA2Engine;
            this.RandomEngine = Prng;

            Array.Copy(OId, this.OId, Math.Min(OId.Length, 3));
            _N = 1 << M;
            _T = T;

            if (T < 0)
                throw new MPKCException("MPKCParameters:Ctor", "T must be positive!", new ArgumentException());
            if (T > N)
                throw new MPKCException("MPKCParameters:Ctor", "T must be less than n = 2^m!", new ArgumentOutOfRangeException());

            if ((PolynomialRingGF2.Degree(FieldPoly) == M) && (PolynomialRingGF2.IsIrreducible(FieldPoly)))
                _fieldPoly = FieldPoly;
            else
                throw new MPKCException("MPKCParameters:Ctor", "Polynomial is not a field polynomial for GF(2^m)", new InvalidDataException());
        }

        private MPKCParameters()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCParameters()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Public key from a byte array.
        /// </summary>
        /// 
        /// <param name="ParamArray">The byte array containing the parameters</param>
        /// 
        /// <returns>An initialized MPKCParameters class</returns>
        public static MPKCParameters From(byte[] ParamArray)
        {
            return From(new MemoryStream(ParamArray));
        }

        /// <summary>
        /// Read a Parameters file from a byte array.
        /// </summary>
        /// 
        /// <param name="ParamStream">The byte array containing the params</param>
        /// 
        /// <returns>An initialized MPKCParameters class</returns>
        public static MPKCParameters From(Stream ParamStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(ParamStream);
                McElieceCiphers eng = (McElieceCiphers)reader.ReadInt32();
                Digests dgt = (Digests)reader.ReadInt32();
                Prngs rnd = (Prngs)reader.ReadInt32();
                int m = reader.ReadInt32();
                int t = reader.ReadInt32();
                int fp = reader.ReadInt32();
                byte[] oid = reader.ReadBytes(3);

                return new MPKCParameters(m, t, fp, oid, eng, dgt, rnd);
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Returns the current parameter set as an ordered byte array
        /// </summary>
        /// 
        /// <returns>McElieceParameters as a byte array</returns>
        public byte[] ToBytes()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write((int)CCA2Engine);
            writer.Write((int)Digest);
            writer.Write((int)RandomEngine);
            writer.Write(M);
            writer.Write(T);
            writer.Write(FieldPolynomial);
            writer.Write(OId);
            writer.Seek(0, SeekOrigin.Begin);

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Returns the current parameter set as a MemoryStream
        /// </summary>
        /// 
        /// <returns>McElieceParameters as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes the parameter set to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">McElieceParameters as a byte array; can be initialized as zero bytes</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the parameter set to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">McElieceParameters as a byte array; array must be initialized and of sufficient length</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="MPKCException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new MPKCException("MPKCParameters:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the parameter set to an output stream
        /// </summary>
        /// 
        /// <param name="Output">Output stream</param>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (IOException e)
            {
                throw new MPKCException(e.Message);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            int result = 1;

            result += 31 * (int)Digest;
            result += 31 * (int)CCA2Engine;
            result += 31 * (int)RandomEngine;
            result += 31 * M;
            result += 31 * N;
            result += 31 * T;
            result += 31 * FieldPolynomial;

            return result;
        }

        /// <summary>
        /// Compare this object instance with another
        /// </summary>
        /// 
        /// <param name="Obj">Object to compare</param>
        /// 
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(Object Obj)
        {
            if (this == Obj)
                return true;
            if (Obj == null && this != null)
                return false;

            MPKCParameters other = (MPKCParameters)Obj;
            if (Digest != other.Digest)
                return false;
            if (CCA2Engine != other.CCA2Engine)
                return false;
            if (RandomEngine != other.RandomEngine)
                return false;
            if (M != other.M)
                return false;
            if (N != other.N)
                return false;
            if (T != other.T)
                return false;
            if (FieldPolynomial != other.FieldPolynomial)
                return false;

            return true;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this McElieceParameters instance
        /// </summary>
        /// 
        /// <returns>McElieceParameters copy</returns>
        public object Clone()
        {
            return new MPKCParameters(M, T, FieldPolynomial, _oId, _cca2Engine, _dgtEngine, _rndEngine);
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
                    _N = 0;
                    _M = 0;
                    _T = 0;
                    _fieldPoly = 0;
                }
                finally
                {
                    _isDisposed = true;
                }
            }
        }
        #endregion
    }
}
