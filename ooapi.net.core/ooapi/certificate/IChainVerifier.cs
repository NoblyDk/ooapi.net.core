using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace org.openoces.ooapi.certificate
{
    public interface IChainVerifier
    {
        Task<bool> VerifyTrust(OcesCertificate certificate);
        Task<bool> VerifyTrust(X509Certificate2 certificate, Ca signingCa);
    }
}