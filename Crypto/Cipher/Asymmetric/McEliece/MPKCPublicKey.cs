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
    public class MPKCPublicKey : IAsymmetricKey, ICloneable, IDisposable
    {
        #region Constants
        private const int OID_LENGTH = 32;
        #endregion

        #region Fields
        private bool _isDisposed = false;
        // the OID of the algorithm
        private byte[] _Oid;
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
        /// Get: Returns the Oid string
        /// </summary>
        public byte[] OID
        {
            get { return _Oid; }
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
        /// <param name="Oid">The 32 byte identifier</param>
        /// <param name="N">The length of the code</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="G">The generator matrix</param>
        internal MPKCPublicKey(byte[] Oid, int N, int T, GF2Matrix G)
        {
            _Oid = new byte[OID_LENGTH];
            Array.Copy(Oid, _Oid, Math.Min(Oid.Length, OID_LENGTH));
            _N = N;
            _T = T;
            _G = new GF2Matrix(G);
        }

        /// <summary>
        /// Constructor used by McElieceKeyFactory
        /// </summary>
        /// 
        /// <param name="Oid">The 32 byte identifier</param>
        /// <param name="T">The error correction capability of the code</param>
        /// <param name="N">The length of the code</param>
        /// <param name="G">The encoded generator matrix</param>
        public MPKCPublicKey(byte[] Oid, int T, int N, byte[] G)
        {
            _Oid = new byte[OID_LENGTH];
            Array.Copy(Oid, _Oid, Math.Min(Oid.Length, OID_LENGTH));
            _N = N;
            _T = T;
            _G = new GF2Matrix(G);
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
        /// <para>The array can contain only the public key.</para>
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the key</param>
        /// 
        /// <returns>An initialized MPKCPublicKey class</returns>
        public static MPKCPublicKey From(byte[] KeyArray)
        {
            return From(new MemoryStream(KeyArray));// ToDo: offset/length? for stream?
        }

        /// <summary>
        /// Read a Public key from a byte array.
        /// <para>The stream can contain only the public key.</para>
        /// </summary>
        /// 
        /// <param name="KeyStream">The byte array containing the key</param>
        /// 
        /// <returns>An initialized MPKCPublicKey class</returns>
        public static MPKCPublicKey From(Stream KeyStream)
        {
            try
            {
                KeyStream.Seek(0, SeekOrigin.Begin);
                BinaryReader reader = new BinaryReader(KeyStream);
                byte[] oid = reader.ReadBytes(OID_LENGTH);
                int n = reader.ReadInt32();
                int t = reader.ReadInt32();
                byte[] encG = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
                MPKCPublicKey pubKey = new MPKCPublicKey(oid, t, n, encG);

                return pubKey;
            }
            catch
            {
                throw;
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
            writer.Write(OID);
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
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new MPKCException("The output array is too small!");

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
            for (int i = 0; i < OID.Length; i++)
            {
                if (key.OID[i] != OID[i])
                    return false;
            }
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
            for (int i = 0; i < OID.Length; i++)
                code += OID[i];

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
            return new MPKCPublicKey(_Oid, _T, _N, _G);
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
                    if (_Oid != null)
                    {
                        Array.Clear(_Oid, 0, _Oid.Length);
                        _Oid = null;
                    }
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
