using System.Threading.Tasks;
using org.openoces.ooapi.certificate;

namespace org.openoces.ooapi.utils
{
    public interface IOcspClient
    {
        Task<bool> IsValid(IOcesCertificate certificate);
    }
}