using System.Threading.Tasks;

namespace org.openoces.ooapi.ping
{
    public interface IRidAliveTester
    {
        Task PingRidAsync();
    }
}