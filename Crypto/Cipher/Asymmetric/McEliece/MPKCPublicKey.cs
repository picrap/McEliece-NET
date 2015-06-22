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
    /// A McEliece public key
    /// </summary>
    public sealed class MPKCPublicKey : IAsymmetricKey
    {
        #region Fields
        private bool _isDisposed = false;
        // the length of the code
        private int _N;
        // the error correction capability of the code
        private int _T;
        // the generator matrix
        private GF2Matrix _G;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the length of the code
        /// </summary>
        public int N
        {
            get { return _N; }
        }

        /// <summary>
        /// Get: Returns the error correction capability of the code
        /// </summary>
        public int T
        {
            get { return _T; }
        }

        /// <summary>
        /// Get: Returns the generator matrix
        /// </summary>
        internal GF2Matrix G
        {
            get { return _G; }
        }

        /// <summary>
        /// Get: Returns the dimension of the code
        /// </summary>
        public int K
        {
            get { return _G.RowCount; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="N">The length of the code</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="G">The generator matrix</param>
        internal MPKCPublicKey(int N, int T, GF2Matrix G)
        {
            _N = N;
            _T = T;
            _G = new GF2Matrix(G);
        }

        /// <summary>
        /// Constructor used by McElieceKeyFactory
        /// </summary>
        /// 
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="N">The length of the code</param>
        /// <param name="G">The encoded generator matrix</param>
        public MPKCPublicKey(int T, int N, byte[] G)
        {
            _N = N;
            _T = T;
            _G = new GF2Matrix(G);
        }

        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="MPKCException">Thrown if the key could not be loaded</exception>
        public MPKCPublicKey(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                _N = reader.ReadInt32();
                _T = reader.ReadInt32();
                _G = new GF2Matrix(reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position)));
            }
            catch (IOException ex)
            {
                throw new MPKCException("MPKCPublicKey:CTor", "The Public key could not be loaded!", ex);
            }
        }
        
        /// <summary>
        /// Reconstructs a public key from its <c>byte</c> array representation.
        /// </summary>
        /// 
        /// <param name="Key">The encoded key array</param>
        public MPKCPublicKey(byte[] Key) :
            this(new MemoryStream(Key))
        {
        }

        private MPKCPublicKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCPublicKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Public key from a byte array.
        /// <para>The array can contain only the public key.
        /// Reads from the streams starting (0) position.</para>
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the key</param>
        /// 
        /// <returns>An initialized MPKCPublicKey class</returns>
        public static MPKCPublicKey From(byte[] KeyArray)
        {
            return From(new MemoryStream(KeyArray));
        }

        /// <summary>
        /// Read a Public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the key</param>
        /// 
        /// <returns>An initialized MPKCPublicKey class</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if the stream can not be read</exception>
        public static MPKCPublicKey From(Stream KeyStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(KeyStream);
                int n = reader.ReadInt32();
                int t = reader.ReadInt32();
                byte[] encG = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
                MPKCPublicKey pubKey = new MPKCPublicKey(t, n, encG);

                return pubKey;
            }
            catch (Exception ex)
            {
                throw new MPKCException("MPKCPublicKey:Ctor", ex.Message, ex);
            }
        }

        /// <summary>
        /// Converts the key pair to a byte array
        /// </summary>
        /// 
        /// <returns>The encoded key pair</returns>
        public byte[] ToBytes()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            writer.Write(N);
            writer.Write(T);
            writer.Write(G.GetEncoded());

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Returns the current key pair set as a MemoryStream
        /// </summary>
        /// 
        /// <returns>KeyPair as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            return new MemoryStream(ToBytes());
        }

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">KeyPair as a byte array; can be initialized as zero bytes</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the key pair to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">KeyPair as a byte array; can be initialized as zero bytes</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="MPKCException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new MPKCException("MPKCPublicKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the key pair to an output stream
        /// </summary>
        /// 
        /// <param name="Output">Output Stream</param>
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
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is MPKCPublicKey))
                return false;
            MPKCPublicKey key = (MPKCPublicKey)Obj;

            if (N != key.N)
                return false;
            if (T != key.T)
                return false;
            if (!G.Equals(key.G))
                return false;

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int code = 0;
            code += N * 31;
            code += T * 31;
            code += G.GetHashCode();

            return code;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>MPKCPublicKey copy</returns>
        public object Clone()
        {
            return new MPKCPublicKey(_T, _N, _G);
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
                    if (_G != null)
                    {
                        _G.Clear();
                        _G = null;
                    }
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
