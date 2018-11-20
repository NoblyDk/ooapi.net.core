using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace org.openoces.ooapi.validation
{
    public interface IX509CrlVerifyImpl
    {
        Task Verify(AsymmetricKeyParameter publicKey, X509Crl _crl, byte[] _TbsCertList);
    }
}