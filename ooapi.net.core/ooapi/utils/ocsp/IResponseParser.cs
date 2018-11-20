using System.Threading.Tasks;
using org.openoces.ooapi.certificate;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Ocsp;

namespace org.openoces.ooapi.utils.ocsp
{
    public interface IResponseParser
    {
        Task<bool> CertificateIsValid(CertID id, OcspResp ocspResp, IOcesCertificate certificate);
    }
}