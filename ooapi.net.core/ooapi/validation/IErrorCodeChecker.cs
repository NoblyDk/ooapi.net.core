using System.Threading.Tasks;

namespace org.openoces.ooapi.validation
{
    public interface IErrorCodeChecker
    {
        Task<bool> HasError(string text);
        Task<string> ExtractError(string text);
    }
}