using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    public interface IX509CertificatePropertyExtrator
    {
        Task<string> GetEmailAddress(X509Certificate2 certificate);
        Task<X509KeyUsageExtension> GetKeyUsage(X509Certificate2 certificate);
        Task<string> GetSubjectOrganizationalUnit(X509Certificate2 certificate);
        Task<string> GetSubjectCommonName(X509Certificate2 certificate);
        Task<bool> HasPseudonym(X509Certificate2 certificate);
        Task<string> GetElementInX509Name(X509Certificate2 certificate, string element);
        Task<X509BasicConstraintsExtension> GetBasicConstraints(X509Certificate2 certificate);
        Task<string> GetCertificatePolicyOid(X509Certificate2 certificate);
        Task<string> GetOcspUrl(X509Certificate2 certificate);
        Task<string> GetCaIssuerUrl(X509Certificate2 certificate);
    }
}