using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using org.openoces.ooapi.certificate;

namespace org.openoces.ooapi.environment
{
    public interface IRootCertificates
    {
        Task<Dictionary<OcesEnvironment, X509Certificate2>> TheRootCertificates { get; }

        /// <summary>
        /// Gets root certificate of the given <code>Environment</code>
        /// </summary>
        Task<X509Certificate2> LookupCertificate(OcesEnvironment environment);

        Task<X509Certificate2> LookupCertificateBySubjectDn(X500DistinguishedName subjectDn);
        Task<bool> HasCertificate(OcesEnvironment environment);

        /// <summary>
        /// Gets <code>Environment</code> for given <code>CA</code>
        /// </summary>
        Task<OcesEnvironment> GetEnvironment(Ca ca);
    }
}