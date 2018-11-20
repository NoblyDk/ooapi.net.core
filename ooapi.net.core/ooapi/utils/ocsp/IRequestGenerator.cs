using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using org.openoces.ooapi.certificate;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace org.openoces.ooapi.utils.ocsp
{
    public interface IRequestGenerator
    {
        Task<OcspReqAndId> CreateOcspRequest(IOcesCertificate certificate);
        Task<OcspReqAndId> CreateOcspRequest(X509Certificate2 rootCertificate, string serialNumber);
        Task<OcspReqAndId> CreateOcspRequest(X509Certificate rootCertificate, string serialNumber);
    }
}