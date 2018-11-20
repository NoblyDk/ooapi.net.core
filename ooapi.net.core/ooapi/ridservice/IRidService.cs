using System.Threading.Tasks;

namespace org.openoces.ooapi.ridservice
{
    public interface IRidService
    {
        Task Test();
        Task<string> GetCpr(string rid);
    }
}