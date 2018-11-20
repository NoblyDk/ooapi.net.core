using System.Threading.Tasks;

namespace org.openoces.ooapi.signatures
{
    public interface IOpensignSignatureFactory
    {
        Task<OpensignAbstractSignature> GenerateOpensignSignature(string xmlDoc);
    }
}