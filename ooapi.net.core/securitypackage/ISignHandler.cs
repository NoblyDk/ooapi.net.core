using System;
using System.Threading.Tasks;

namespace org.openoces.securitypackage
{
    public interface ISignHandler
    {
        /// <summary>
        /// Given the output data from the Open Sign applet, signed text is extracted if the login data is valid.
        /// </summary>
        /// <param name="loginData">the output data from the Open Sign applet (base64 encoded).</param>
        /// <param name="agreement">the string to match against the signed text in the login data.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or 
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended)</param>.
        /// <returns>true if the signed text matches the agreement parameter</returns>
        /// <throws>AppletException in case the applet returned an error code.</throws>
        Task<SignatureValidationStatus> ValidateSignatureAgainstAgreement(string loginData, string agreement, string stylesheet, string challenge, string logonto);

        Task<SignatureValidationStatus> ValidateSignatureAgainstAgreement(string loginData, string agreement, string challenge, string logonto);
        Task<SignatureValidationStatus> validateSignatureAgainstAgreementPDF(String loginData, String encodedAgreement, String challenge, String logonto);
        Task<string> Base64Encode(string text);
        Task<string> Base64Encode(byte[] data);
        Task<string> Base64Decode(string s);
        Task<string> Base64PDFDecode(string s);
    }
}