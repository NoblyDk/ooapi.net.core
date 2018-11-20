using System;
using System.Threading.Tasks;
using org.openoces.ooapi.environment;

namespace org.openoces.ooapi.validation
{
    public interface ICachedLdapCrlDownloader
    {
        Task<Crl> Download(OcesEnvironment environment, String ldapPath);
    }
}