using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using org.openoces.ooapi.environment;

namespace org.openoces.ooapi.ldap
{
    public interface ILdapFactory
    {
        Task<LdapConnection> CreateLdapConnection(OcesEnvironment environment);
    }
}