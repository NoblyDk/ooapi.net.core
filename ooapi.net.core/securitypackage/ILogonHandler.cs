using System.Threading.Tasks;
using org.openoces.ooapi.certificate;
using org.openoces.serviceprovider;

namespace org.openoces.securitypackage
{
    public interface ILogonHandler
    {
        /// <summary>
        /// Given the output data from the Open Logon applet, the person ID (pid) is extracted if the login data is valid.
        /// </summary>
        /// <param name="loginData">the output data from the Open Logon applet.</param>
        /// <param name="challenge">the challenge applet parameter.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended).</param>
        /// <returns>the pid of the certificate that is used for logging in. Only valid pids are returned.</returns>
        /// <throws>ServiceProviderException in case that no pid can be extracted from the data provided.</throws>
        /// <throws>AppletException in case the applet returned an error code.</throws>
        Task<PersonId> ValidateAndExtractPid(string loginData, string challenge, string logonto);

        /// <summary>
        /// Given the output data from the Open Logon applet, the certificate is extracted if the login data is valid.
        /// NB! The validity of the certificate is *NOT* checked 
        /// (i.e. it is not checked if the certificate is valid, invalid, revoked, not yet valid or expired) 
        /// </summary>
        /// <param name="loginData">the output data from the Open Logon applet.</param>
        /// <param name="challenge">the challenge applet parameter.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended).</param>
        /// <returns>the certificate that is used for logging in.</returns>
        Task<OcesCertificate> ValidateSignatureAndExtractCertificate(string loginData, string challenge, string logonto);

        /// <summary>
        /// Given the output data from the Open Logon applet, the certificate extracted if the login data is valid. 
        /// The status of the certificate is checked and a the certificate and its status is returned wrapped in a 
        /// CertificateStatus instance.
        /// </summary>
        /// <param name="loginData">the output data from the Open Logon applet.</param>
        /// <param name="challenge">the challenge applet parameter.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended).</param>
        /// <returns>the certificate that is used for logging in and the status of this certificate (wrapped in a CertificateStatus instance)</returns>
        Task<CertificateAndStatus> ValidateAndExtractCertificateAndStatus(string loginData, string challenge, string logonto);
    }
}