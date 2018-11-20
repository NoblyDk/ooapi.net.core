using System.Threading.Tasks;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.validation;

namespace org.openoces.serviceprovider
{
    public interface ICertificateRevocationHandler
    {
        /// <summary>
        /// Retrieves the full CRL for the given certificate
        /// </summary>
        /// <param name="certificate">to retrieve full CRL for</param>
        /// <returns>full CRL for the given certificate</returns>
        Task<Crl> RetrieveFullCrl(OcesCertificate certificate);

        /// <summary>
        /// This method verifies a certificate by calling the OCSP used in current Environment 
        /// </summary>
        /// <param name="certificate">certificate to verify</param>
        /// <returns>true if certificate is revoked else false</returns>
        Task<bool> VerifyCertificateWithOcsp(OcesCertificate certificate);
    }
}