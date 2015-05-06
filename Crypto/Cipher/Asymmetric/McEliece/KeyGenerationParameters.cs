#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace McElieceEngine.McEliece
{
    /// <summary>
    /// McEliece Key Generation Parameters
    /// </summary>
    public class McElieceKeyGenerationParameters : KeyGenerationParameters
    {
        private MPKCParameters _param;

        /// <summary>
        /// 
        /// </summary>
        /// 
        /// <param name="Rng"></param>
        /// <param name="Param"></param>
        public McElieceKeyGenerationParameters(SecureRandom Rng, MPKCParameters Param) :
            base(Rng, 256)
        {
            // XXX key size?
            _param = Param;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public MPKCParameters GetParameters()
        {
            return _param;
        }
    }
}
