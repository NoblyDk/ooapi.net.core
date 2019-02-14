using System;
using System.Threading.Tasks;

namespace org.openoces.ooapi.web
{
    public interface IJSONParametersGenerator
    {
        Task SetParameter(string key, string value);
        Task SetParameter(string key, string value, Boolean base64Encode);
        Task SetAdditionalParameter(string key, string value);
        Task SetAdditionalParameter(string key, string value, Boolean base64Encode);
        Task<string> GenerateParameters(string pfxFile, string pfxPassword);
        Task<string> GenerateParameters(byte[] pfxBytes, string pfxPassword);
        Task<string> GenerateParameters(byte[] pfxBytes);
    }
}