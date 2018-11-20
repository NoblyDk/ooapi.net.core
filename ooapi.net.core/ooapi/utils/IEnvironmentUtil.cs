using System.Net;
using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    public interface IEnvironmentUtil
    {
        SecurityProtocolType TLS12 { get; }
        Task EnableProtocolIfSupportedByPlatform(SecurityProtocolType protocol);
        Task<bool> IsProtocolSupported(SecurityProtocolType protocol);
        Task<bool> IsProtocolEnabled(SecurityProtocolType protocol);
        Task DissableProtocol(SecurityProtocolType protocol);
        Task EnableProtocol(SecurityProtocolType protocol);
    }
}