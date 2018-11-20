using org.openoces.ooapi.certificate;

namespace org.openoces.securitypackage
{
    public interface ISignatureValidationStatus
    {
        ///  <value>Token representing the userID to be stored. Optional.</value>
        string RememberUserIdToken { get; }

        OcesCertificate Certificate { get; }
    }
}