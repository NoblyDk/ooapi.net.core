using System.Threading.Tasks;
using org.openoces.ooapi.validation;

namespace org.openoces.serviceprovider
{
    public interface IServiceProviderSetup
    {
        Task SetRevocationChecker(IRevocationChecker revocationChecker);
        IRevocationChecker CurrentChecker { get; }
        /// <summary>
        /// Sets the environment to OCES-II production. This is the default.
        /// </summary>
        Task SetEnvironmentToOcesIIProduction();

        Task SetEnvironmentToOcesIIPreProd();
    }
}