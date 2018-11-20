using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    public interface IProperties
    {
        Task<string> Get(string name);

        /// <summary>
        /// Determines whether or not the given configuration property is defined or not.
        /// </summary>
        Task<bool> IsDefined(string name);

        Task<int> GetHttpCrlCacheTimeout();
        Task<int> GetLdapCrlCacheTimeout();
        Task<string> icaCNToURL(string icaCN);
    }
}