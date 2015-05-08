#region Directives
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// This class is a utility class for parallel processing
    /// </summary>
    public class ParallelUtils
    {
        #region Fields
        private static bool _frcLinear = false;
        #endregion

        /// <summary>
        /// Get/Set: Force uni-processing (IsParallel returns false)
        /// </summary>
        public static bool ForceLinear
        {
            get { return _frcLinear; }
            set { _frcLinear = value; }
        }

        /// <summary>
        /// Get: Returns true for multi processor system
        /// </summary>
        public static bool IsParallel
        {
            get { return Environment.ProcessorCount > 1 && _frcLinear == false; }
        }

        /// <summary>
        /// A parallel While function
        /// </summary>
        /// 
        /// <param name="Condition">The while conditional</param>
        /// <param name="Body">The functions body</param>
        public static void While(Func<bool> Condition, Action Body)
        {
            Parallel.ForEach(Until(Condition), dlg => Body());
        }

        private static IEnumerable<bool> Until(Func<bool> Condition)
        {
            while (Condition()) yield return true;
        }
    }
}
