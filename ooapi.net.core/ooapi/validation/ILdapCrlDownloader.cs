using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using org.openoces.ooapi.environment;

namespace org.openoces.ooapi.validation
{
    public interface ILdapCrlDownloader
    {
        Task<Crl> DownloadAsync(OcesEnvironment environment, string ldapPath);
        Task<X509Certificate2> DownloadCertificate(OcesEnvironment env, string ldapPath);
    }
}