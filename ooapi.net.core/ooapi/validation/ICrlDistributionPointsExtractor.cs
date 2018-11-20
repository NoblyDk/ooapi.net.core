using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace org.openoces.ooapi.validation
{
    public interface ICrlDistributionPointsExtractor
    {
        Task<CrlDistributionPoints> ExtractCrlDistributionPointsAsync(X509Certificate2 certificate);
    }
}