#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.McEliece
{
    /// <summary>
    /// This class implements key pair generation of the McEliece Public Key Cryptosystem (McEliecePKC) using CCA2 Secure variants.
    /// </summary>
    /// <example>
    /// <description>Example of creating a keypair:</description>
    /// <code>
    /// MPKCParameters encParams = new MPKCParameters(11, 40, McElieceCiphers.Fujisaki);
    /// MPKCKeyGenerator keyGen = new MPKCKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    ///     <revision date="2015/01/23" version="1.4.0.0">Initial release</revision>
    /// </revisionHistory>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <description>The algorithm is given the parameters m and t or the key size n as input. Then, the following matrices are generated:</description> 
    /// <list type="table">
    /// <item><description>The public key is (n, t, G). The private key is (m, k, field polynomial, Goppa polynomial, H, S, P, setJ).</description></item>
    /// <item><description>G' is a k x n generator matrix of a binary irreducible (n,k) Goppa code GC which can correct up to t errors where n = 2^m and k is chosen maximal, i.e. k &lt;= n - mt.</description></item>
    /// <item><description>H is an mt x n check matrix of the Goppa code GC.</description></item>
    /// <item><description>S is a k x k random binary non-singular matrix.</description></item>
    /// <item><description>P is an n x n random permutation matrix.</description></item>
    /// <item><description>Then, the algorithm computes the k x n matrix G = SG'P.</description></item>
    /// </list> 
    /// </remarks>
    public sealed class MPKCKeyGenerator
    {
        #region Fields
        private MPKCParameters _mcElieceParams;
        private int _M;
        private int _N;
        private int _T;
        private int _fieldPoly;
        private SecureRandom _secRnd;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CiphersParams">The MPKCParameters instance containing thecipher settings</param>
        public MPKCKeyGenerator(MPKCParameters CiphersParams)
        {
            _mcElieceParams = (MPKCParameters)CiphersParams;
            // set source of randomness
            _secRnd = new SecureRandom();
            _M = _mcElieceParams.M;
            _N = _mcElieceParams.N;
            _T = _mcElieceParams.T;
            _fieldPoly = _mcElieceParams.FieldPolynomial;
        }

        private MPKCKeyGenerator()
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generate an encryption Key pair
        /// </summary>
        /// 
        /// <returns>A McElieceKeyPair containing public and private keys</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            // finite field GF(2^m)
            GF2mField field = new GF2mField(_M, _fieldPoly); 
            // irreducible Goppa polynomial
            PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, _T, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, _secRnd);
            PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);
            // matrix for computing square roots in (GF(2^m))^t
            PolynomialGF2mSmallM[] qInv = ring.SquareRootMatrix;
            // generate canonical check matrix
            GF2Matrix h = GoppaCode.CreateCanonicalCheckMatrix(field, gp);
            // compute short systematic form of check matrix
            GoppaCode.MaMaPe mmp = GoppaCode.ComputeSystematicForm(h, _secRnd);
            GF2Matrix shortH = mmp.SecondMatrix;
            Permutation p = mmp.Permutation;
            // compute short systematic form of generator matrix
            GF2Matrix shortG = (GF2Matrix)shortH.ComputeTranspose();
            // obtain number of rows of G (= dimension of the code)
            int k = shortG.RowCount;
            // generate keys
            IAsymmetricKey pubKey = new MPKCPublicKey(_N, _T, shortG);
            IAsymmetricKey privKey = new MPKCPrivateKey(_N, k, field, gp, p, h, qInv);

            // return key pair
            return new MPKCKeyPair(pubKey, privKey);            
        }
        #endregion
    }
}
