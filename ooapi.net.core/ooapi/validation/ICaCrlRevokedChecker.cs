using System.Threading.Tasks;
using org.openoces.ooapi.certificate;

namespace org.openoces.ooapi.validation
{
    public interface ICaCrlRevokedChecker : IRevocationChecker
    {
      
        Task<bool> IsRevoked(Ca ca);

        /// <summary>
        /// Downloads the full CRL for the given certificate.
        /// </summary>
        /// <param name="certificate">certificate to download full CRL for</param>
        /// <returns>full CRL for given certificate</returns>
        Task<Crl> DownloadCrl(IOcesCertificate certificate);

        Task<Crl> DownloadCrl(Ca ca);
        Task<Crl> DownloadCrl(string crlDistributionPoint);
    }
}