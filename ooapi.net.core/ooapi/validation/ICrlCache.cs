using System.Threading.Tasks;

namespace org.openoces.ooapi.validation
{
    public interface ICrlCache
    {
        Task<Crl> GetCrlAsync(string key);
        Task DownloadCrlAndUpdateCacheAsync(string key, IDownloadableCrlJob job);
        Task<bool> IsValidAsync(string key);
        Task<bool> CheckOnlyIfCrlIsValidAsync(string key);
    }
}