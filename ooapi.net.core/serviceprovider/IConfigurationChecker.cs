using System.Threading.Tasks;
using org.openoces.ooapi.certificate;

namespace org.openoces.serviceprovider
{
    public interface IConfigurationChecker
    {
        /// <summary>
        /// This method is used verify that a connection can be made to the LDAP directory holding
        /// the root certificate for all environments begin set using the {@link Environments} class.
        /// </summary>
        Task VerifyRootCertificateFromLdapAsync();

        /// <summary>
        /// Checks that a full CRL can be retrieved and is valid. Expects that an environment has been set up.
        /// </summary>
        /// <returns><code>true</code> if the CRL is retrieved or else false</returns>
        Task<bool> VerifyFullCrlAsync(OcesCertificate ocesCertificate);

        /// <summary>
        /// Checks whether a connection can be made to the PID/CPR service by means of testing if 
        /// the PID service is alive and reachable.
        /// </summary>
        /// <returns><code>true</code> if the PID/CPR service can be reached by the current environment setup</returns>
        Task<bool> VerifyPidServiceAsync();

        Task<bool> VerifyRidServiceAsync();

        /// <summary>
        /// Checks whether a connection can be made to the PID/CPR web service by means of calling 
        /// the test method on the web service
        /// </summary>
        /// <returns><code>true</code> if a connection can be made</returns>
        Task<bool> MakeTestConnectionToPidcprServiceAsync();

        /// <summary>
        /// This method calls the OCSP configured for current <code>Environment</code>.
        /// This method further validate the root certificate against the OCSP.
        /// </summary>
        /// <returns><code>true</code> if call went well, else <code>false</code></returns>
        Task<bool> CanCallOcspAsync(string ocspUrl);
    }
}