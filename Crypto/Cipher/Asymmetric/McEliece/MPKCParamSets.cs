namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece
{
    /// <summary>
    /// Contains sets of predefined McEliece parameters
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
        /// <summary>
        /// Low security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:95, MaxText:201, K:1608 N:2048, PublicKey Size:88488, PrivateKey Size:119071</para>
        /// </summary>
        public static MPKCParameters MPKCFM11T40S256 = new MPKCParameters(11, 40, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:98, MaxText:190, K:1520 N:2048, PublicKey Size:100368, PrivateKey Size:142531</para>
        /// </summary>
        public static MPKCParameters MPKCFM11T48S256 = new MPKCParameters(11, 48, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Low to Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:108, MaxText:465, K:3724, N:4096, PublicKey Size: 175076, PrivateKey Size:200119</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T31S256 = new MPKCParameters(12, 31, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:129, MaxText:450, K:3604, N:4096, PublicKey Size: 223496, PrivateKey Size:262519</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T41S256 = new MPKCParameters(12, 41, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:131?, MaxText:440, K:3520, N:4096, PublicKey Size: 253488, PrivateKey Size:306371</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T48S256 = new MPKCParameters(12, 48, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:133?, MaxText:431, K:3448, N:4096, PublicKey Size: 306371, PrivateKey Size:344039</para>
        /// </summary>
        public static MPKCParameters MPKCFM12T54K256 = new MPKCParameters(12, 54, McElieceCiphers.Fujisaki, Digests.Keccak256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and SHA-256
        /// <para>Security:128, MaxText:976, K:7815, N:8192, PublicKey Size: 375168, PrivateKey Size:403733</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T29S256 = new MPKCParameters(13, 29, McElieceCiphers.Fujisaki, Digests.SHA256);

        /// <summary>
        /// Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:136, MaxText:952, K:7620, N:8192, PublicKey Size: 548688, PrivateKey Size:604893</para>
        /// </summary>
        public static MPKCParameters MPKCFM13T440K256 = new MPKCParameters(13, 44, McElieceCiphers.Fujisaki, Digests.Keccak256);

        /// <summary>
        /// Low to Medium security; uses the Fujisaki cipher and Keccak 256
        /// <para>Security:115, MaxText:2006, K:16048, N:16384, PublicKey Size: 674064, PrivateKey Size:721847</para>
        /// </summary>
        public static MPKCParameters MPKCFM14T24K256 = new MPKCParameters(14, 24, McElieceCiphers.Fujisaki, Digests.Keccak256);
    }
}
