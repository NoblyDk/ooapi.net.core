using System.Threading.Tasks;
using Org.BouncyCastle.Ocsp;

namespace org.openoces.ooapi.utils.ocsp
{
    public interface IRequester
    {
        Task<OcspResp> SendAsync(OcspReq ocspRequest, string url);
    }
}