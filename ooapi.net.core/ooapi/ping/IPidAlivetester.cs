using System.Threading.Tasks;

namespace org.openoces.ooapi.ping
{
    public interface IPidAlivetester
    {
        Task PingPidAsync();
    }
}