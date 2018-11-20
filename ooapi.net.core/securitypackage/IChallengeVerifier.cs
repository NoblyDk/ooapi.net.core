using System.Threading.Tasks;
using org.openoces.ooapi.signatures;

namespace org.openoces.securitypackage
{
    public interface IChallengeVerifier
    {
        Task VerifyChallenge(OpensignAbstractSignature signature, string challenge);
    }
}