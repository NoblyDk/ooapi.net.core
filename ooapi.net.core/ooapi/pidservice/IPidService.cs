using System.Threading.Tasks;

namespace org.openoces.ooapi.pidservice
{
    public interface IPidService
    {
        Task TestAsync();
        Task TestAsync(string serviceUrl);
        Task<int> TestConnectionAsync(int value);
        Task<string> LookupCprAsync(string pid, string callerSpid);
        Task<bool> MatchAsync(string cpr, string pid, string callerSpid);
    }
}