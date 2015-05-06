#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Exceptions
{
    /// <summary>
    /// The libraries base exception type
    /// </summary>
    public class MPKCException : Exception
    {
        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Msg">A custom message or error data</param>
        public MPKCException(String Msg) :
            base(Msg)
        {
        }
    }
}
