using System;
using System.IO;
using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    public interface INemIdHttpClient
    {
        Task<byte[]> Download(string location);
    }
}