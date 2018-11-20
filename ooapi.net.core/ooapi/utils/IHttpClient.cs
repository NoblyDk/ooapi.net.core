using System;
using System.IO;
using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    public interface IHttpClient
    {
        Task<byte[]> Download(string location);
        Task<byte[]> ReadBytesFromUri(Uri uri);
        Task<byte[]> ReadBytesFromStream(Stream responseStream);
    }
}