using System.Threading.Tasks;

namespace org.openoces.ooapi.ping
{
    public interface IOcspAliveTester
    {
        /// <summary>
        /// This method makes a ping to all OCSPs defined in the <code>Environments</code>.
        /// It also calls the OCSPs with root certificate for current environment.
        /// </summary>
        /// <returns>True if all pings went good else false</returns>
        Task<bool> PingOcsp(string ocspUrl);
    }
}