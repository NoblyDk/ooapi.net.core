using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace org.openoces.ooapi.environment
{
    public interface IEnvironments
    {
        Task<OcesEnvironment> getOces_II_Environment();
        IEnumerable<OcesEnvironment> TheTrustedEnvironments { get; }
        /// <summary>
        /// Sets the environments that must be supported in this execution context.
        /// The list of environments that must be supported can only be set once in a specific execution context.
        /// </summary>
        Task OcesEnvironments(IList<OcesEnvironment> ocesEnvironments);
        
        /// <summary>
        /// Gets list of <code>X509Certificate</code>s of the CAs that are currently trusted.
        /// </summary>
        Task<IEnumerable<X509Certificate2>> TrustedCertificates();
    }
}