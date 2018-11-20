using System.Threading.Tasks;

namespace org.openoces.ooapi.web
{
    public interface ISigner
    {
        Task<string> GetCertificateAsync(string pfxFile, string pfxPassword);
        Task<byte[]> CalculateSignatureAsync(byte[] data, string pfxFile, string pfxPassword);
    }
}