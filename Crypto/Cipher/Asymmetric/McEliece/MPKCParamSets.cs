#region Directives
using VTDev.Libraries.CEXEngine.Exceptions;
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece
{
    /// <summary>
    /// Contains sets of predefined McEliece parameters
    /// <para>Use the FromId(byte[]) or FromName(MPKCParamSets) to return a deep copy of a parameter set</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <description><h4>Guiding Publications:</h4></description>
    /// <list type="number">
    /// <item><description>McEliece Handbook of Applied Cryptography: Chapter 8<cite>McEliece Handbook of Applied Cryptography</cite>.</description></item>
    /// <item><description>Selecting Parameters for Secure McEliece-based Cryptosystems<cite>McEliece Parameters</cite>.</description></item>
    /// <item><description>Weak keys in the McEliece public-key cryptosystem<cite>McEliece Weak keys</cite>.</description></item>
    /// <item><description>McBits: fast constant-time code-based cryptography<cite>McEliece McBits</cite>.</description></item>
    /// </list>
    /// </remarks>
    public static class MPKCParamSets
    {
        #region Enums
        /// <summary>
        /// Set id is defined as: Cipher(Fujisaki default), T value, M value, Digest family, Digest size 
        /// <para>FM11T40S256 = F(Fujisake): M11: T40: S(SHA-2): 256</para>
        /// </summary>
        public enum MPKCParamNames : int
        {
            /// <summary>
            /// Low security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:95, MaxText:201, K:1608 N:2048, PublicKey Size:88488, PrivateKey Size:119071</para>
            /// </summary>
            FM11T40S256,
            /// <summary>
            /// Low security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:98, MaxText:190, K:1520 N:2048, PublicKey Size:100368, PrivateKey Size:142531</para>
            /// </summary>
            FM11T48S256,
            /// <summary>
            /// Low to Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:108, MaxText:465, K:3724, N:4096, PublicKey Size: 175076, PrivateKey Size:200119</para>
            /// </summary>
            FM12T31S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:129, MaxText:450, K:3604, N:4096, PublicKey Size: 223496, PrivateKey Size:262519</para>
            /// </summary>
            FM12T41S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:131?, MaxText:440, K:3520, N:4096, PublicKey Size: 253488, PrivateKey Size:306371</para>
            /// </summary>
            FM12T48S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and Keccak 256
            /// <para>Security:133?, MaxText:431, K:3448, N:4096, PublicKey Size: 306371, PrivateKey Size:344039</para>
            /// </summary>
            FM12T54K256,
            /// <summary>
            /// High security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:148?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928</para>
            /// </summary>
            FM12T67S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and SHA-256
            /// <para>Security:128, MaxText:976, K:7815, N:8192, PublicKey Size: 375168, PrivateKey Size:403733</para>
            /// </summary>
            FM13T29S256,
            /// <summary>
            /// Medium security; uses the Fujisaki cipher and Keccak 256
            /// <para>Security:136, MaxText:952, K:7620, N:8192, PublicKey Size: 548688, PrivateKey Size:604893</para>
            /// </summary>
            FM13T44K256,
            /// <summary>
            /// High security; uses the Fujisaki cipher and SHA-256 (slow)
            /// <para>Security:190?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928</para>
            /// </summary>
            FM13T95S256,
            /// <summary>
            /// Low to Medium security; uses the Fujisaki cipher and Keccak 256
            /// <para>Security:115, MaxText:2006, K:16048, N:16384, PublicKey Size: 674064, PrivateKey Size:721847</para>
            /// </summary>
            FM14T24K256
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Retrieve a parameter set by its identity code
        /// </summary>
        /// 
        /// <param name="OId">The 3 byte parameter set identity code</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if an invalid or unknown OId is specified</exception>
        public static MPKCParameters FromId(byte[] OId)
        {
            if (OId == null)
                throw new MPKCException("MPKCParamSets:FromId", "OId can not be null!", new ArgumentException());
            if (OId.Length != 3)
                throw new MPKCException("MPKCParamSets:FromId", "OId must be 3 bytes in length!", new ArgumentException());
            if (OId[0] != 1)
                throw new MPKCException("MPKCParamSets:FromId", "OId is not a valid MPKC parameter id!", new ArgumentException());

            if (OId[1] == 1)
            {
                if (OId[2] == 0)
                    return (MPKCParameters)MPKCFM11T40S256.Clone();
                else if (OId[2] == 1)
                    return (MPKCParameters)MPKCFM11T48S256.Clone();
            }
            else if (OId[1] == 2)
            {
                if (OId[2] == 0)
                    return (MPKCParameters)MPKCFM12T31S256.Clone();
                else if (OId[2] == 1)
                    return (MPKCParameters)MPKCFM12T41S256.Clone();
                else if (OId[2] == 2)
                    return (MPKCParameters)MPKCFM12T48S256.Clone();
                else if (OId[2] == 3)
                    return (MPKCParameters)MPKCFM12T54K256.Clone();
                else if (OId[2] == 4)
                    return (MPKCParameters)MPKCFM12T67S256.Clone();
            }
            else if (OId[1] == 3)
            {
                if (OId[2] == 0)
                    return (MPKCParameters)MPKCFM13T29S256.Clone();
                else if (OId[2] == 1)
                    return (MPKCParameters)MPKCFM13T44K256.Clone();
                else if (OId[2] == 2)
                    return (MPKCParameters)MPKCFM13T95S256.Clone();
            }
            else if (OId[1] == 4)
            {
                if (OId[2] == 0)
                    return (MPKCParameters)MPKCFM14T24K256.Clone();
            }

            throw new MPKCException("MPKCParamSets:FromId", "OId does not identify a valid param set!", new ArgumentException());
        }

        /// <summary>
        /// Retrieve a parameter set by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>A populated parameter set</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if an invalid or unknown OId is specified</exception>
        public static MPKCParameters FromName(MPKCParamNames Name)
        {
            switch (Name)
            {
                case MPKCParamNames.FM11T40S256:
                    return (MPKCParameters)MPKCFM11T40S256.Clone();
                case MPKCParamNames.FM11T48S256:
                    return (MPKCParameters)MPKCFM11T48S256.Clone();
                case MPKCParamNames.FM12T31S256:
                    return (MPKCParameters)MPKCFM12T31S256.Clone();
                case MPKCParamNames.FM12T41S256:
                    return (MPKCParameters)MPKCFM12T41S256.Clone();
                case MPKCParamNames.FM12T48S256:
                    return (MPKCParameters)MPKCFM12T48S256.Clone();
                case MPKCParamNames.FM12T54K256:
                    return (MPKCParameters)MPKCFM12T54K256.Clone();
                case MPKCParamNames.FM12T67S256:
                    return (MPKCParameters)MPKCFM12T67S256.Clone();
                case MPKCParamNames.FM13T29S256:
                    return (MPKCParameters)MPKCFM13T29S256.Clone();
                case MPKCParamNames.FM13T44K256:
                    return (MPKCParameters)MPKCFM13T44K256.Clone();
                case MPKCParamNames.FM13T95S256:
                    return (MPKCParameters)MPKCFM13T95S256.Clone();
                case MPKCParamNames.FM14T24K256:
                    return (MPKCParameters)MPKCFM14T24K256.Clone();
                default:
                    throw new MPKCException("MPKCParamSets:FromName", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }

        /// <summary>
        /// Retrieve the parameter OId by its enumeration name
        /// </summary>
        /// 
        /// <param name="Name">The enumeration name</param>
        /// 
        /// <returns>The 3 byte OId field</returns>
        /// 
        /// <exception cref="MPKCException">Thrown if an invalid or unknown OId is specified</exception>
        public static byte[] GetID(MPKCParamNames Name)
        {
            switch (Name)
            {
                case MPKCParamNames.FM11T40S256:
                    return new byte[] { 1, 1, 0 };
                case MPKCParamNames.FM11T48S256:
                    return new byte[] { 1, 1, 1 };
                case MPKCParamNames.FM12T31S256:
                    return new byte[] { 1, 2, 0 };
                case MPKCParamNames.FM12T41S256:
                    return new byte[] { 1, 2, 1 };
                case MPKCParamNames.FM12T48S256:
                    return new byte[] { 1, 2, 2 };
                case MPKCParamNames.FM12T54K256:
                    return new byte[] { 1, 2, 3 };
                case MPKCParamNames.FM12T67S256:
                    return new byte[] { 1, 2, 4 };
                case MPKCParamNames.FM13T29S256:
                    return new byte[] { 1, 3, 0 };
                case MPKCParamNames.FM13T44K256:
                    return new byte[] { 1, 3, 1 };
                case MPKCParamNames.FM13T95S256:
                    return new byte[] { 1, 3, 2 };
                case MPKCParamNames.FM14T24K256:
                    return new byte[] { 1, 4, 0 };
                default:
                    throw new MPKCException("MPKCParamSets:GetID", "The Parameter Name is not recognized!", new ArgumentException());
            }
        }
        #endregion

        #region Parameter Sets
        // Note: Oid = family, mbase, ordinal
        /// <summary>
        /// Low security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:95, MaxText:201, K:1608 N:2048, PublicKey Size:88488, PrivateKey Size:119071</para>
        /// </summary>
        public static MPKCParameters MPKCFM11T40S256 = new MPKCParameters(11, 40, new byte[] { 1, 1, 0 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:98, MaxText:190, K:1520 N:2048, PublicKey Size:100368, PrivateKey Size:142531</para>
        /// </summary>
        public static MPKCParameters MPKCFM11T48S256 = new MPKCParameters(11, 48, new byte[] { 1, 1, 1 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low to Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:108, MaxText:465, K:3724, N:4096, PublicKey Size: 175076, PrivateKey Size:200119</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T31S256 = new MPKCParameters(12, 31, new byte[] { 1, 2, 0 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:129, MaxText:450, K:3604, N:4096, PublicKey Size: 223496, PrivateKey Size:262519</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T41S256 = new MPKCParameters(12, 41, new byte[] { 1, 2, 1 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:131?, MaxText:440, K:3520, N:4096, PublicKey Size: 253488, PrivateKey Size:306371</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T48S256 = new MPKCParameters(12, 48, new byte[] { 1, 2, 2 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:133?, MaxText:431, K:3448, N:4096, PublicKey Size: 306371, PrivateKey Size:344039</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T54K256 = new MPKCParameters(12, 54, new byte[] { 1, 2, 3 }, McElieceCiphers.Fujisaki, Digests.Keccak256);

        /// <summary>
        /// High security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:148?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T67S256 = new MPKCParameters(12, 67, new byte[] { 1, 2, 4 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:128, MaxText:976, K:7815, N:8192, PublicKey Size: 375168, PrivateKey Size:403733</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T29S256 = new MPKCParameters(13, 29, new byte[] { 1, 3, 0 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:136, MaxText:952, K:7620, N:8192, PublicKey Size: 548688, PrivateKey Size:604893</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T44K256 = new MPKCParameters(13, 44, new byte[] { 1, 3, 1 }, McElieceCiphers.Fujisaki, Digests.Keccak256);

        /// <summary>
        /// High security; uses the Fujisaki cipher and SHA-256 (slow)
        /// <para>Security:190?, MaxText:431, K:3292, N:4096, PublicKey Size: 332540, PrivateKey Size:425928</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T95S256 = new MPKCParameters(13, 95, new byte[] { 1, 3, 2 }, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low to Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:115, MaxText:2006, K:16048, N:16384, PublicKey Size: 674064, PrivateKey Size:721847</para>
        /// </summary>
        public static MPKCParameters MPKCFM14T24K256 = new MPKCParameters(14, 24, new byte[] { 1, 4, 0 }, McElieceCiphers.Fujisaki, Digests.Keccak256);
        #endregion
    }
}
