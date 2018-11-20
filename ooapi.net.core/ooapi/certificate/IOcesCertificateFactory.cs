using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace org.openoces.ooapi.certificate
{
    public interface IOcesCertificateFactory
    {
        /// <summary>
        ///  Generates an <code>OcesCertificate</code>. The returned <code>OcesCertificate</code> is the end user certificate, which has a parent relation 
        ///  to the certificate of its issuing CA which again can have a parent relation to the certificate of the root CA. 
        ///  The root CA has no parent relation.
        ///  
        /// The factory verifies that each certificate in the certificate chain has been signed by its issuing CA.
        /// </summary>
        /// <param name="certificates">List of certificates to create OcesCertificate chain from.</param>
        /// <returns><code>OcesCertificate</code> with parent relation to (chain of) issuing CAs. Depending on the Subject DN in the 
        /// certificate a <code>PocesCertificate</code>, <code>MocesCertificate</code>, <code>VocesCertificate</code>, or <code>FocesCertificate</code> will be created.</returns>
        ///  <exception cref="org.openoces.ooapi.exceptions.TrustCouldNotBeVerifiedException">when a OcesCertificate in the chain cannot be trusted, i.e. has not been signed by its issuing CA.</exception>
        Task<OcesCertificate> Generate(List<X509Certificate2> certificates);
    }
}