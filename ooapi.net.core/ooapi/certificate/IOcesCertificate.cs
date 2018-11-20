using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using org.openoces.ooapi.validation;

namespace org.openoces.ooapi.certificate
{
    public interface IOcesCertificate
    {
        string SubjectSerialNumber { get; }

        /// <summary>
        /// Gets the signing Certificate Authority (CA) parent relation of this certificate
        /// </summary>
        Ca IssuingCa { get; }

        /// <summary>
        /// Gets the subject CN (common name) of the certificate.
        /// </summary>
        /// <returns>The subject CN (common name) of the certificate.</returns>
        string SubjectCn { get; }

        /// <summary>
        /// Gets the start date of the validity period.
        /// </summary>
        /// <returns>the start date of the validity period.</returns>
        DateTime NotBefore { get; }

        /// <summary>
        /// Gets the end date of the validity period.
        /// </summary>
        /// <returns>the end date of the validity period.</returns>
        DateTime NotAfter { get; }

        /// <summary>
        /// Gets the serial number of certificate. The serial number is unique for all certificates issued by a specific CA. 
        /// </summary>
        /// <returns>
        /// serial number of certificate. The serial number is unique for all certificates issued by a specific CA. 
        /// </returns>
        string SerialNumber { get; }

        /// <summary>
        /// Gets the OCSP URL of the certificate
        /// </summary>
        /// <returns>the OCSP URL of the certificate</returns>
        String OcspUrl { get; }

        /// <summary>
        /// Gets the caIssuer URL of the certificate
        /// </summary>
        /// <returns>the caIssuer URL of the certificate</returns>
        /// <throws>InvalidCaIssuerUrlException in case that no ca issuer url specified in the certificate.</throws>
        String CaIssuerUrl { get; }

        /// <summary>
        /// Gets the distinguished name of the issuer CA.
        /// </summary>
        /// <returns>distinguished name of the issuer CA.</returns>
        string IssuerDn { get; }

        /// <summary>
        /// Gets the distinguished name of this certificate.
        /// </summary>
        /// <returns>the distinguished name of this certificate.</returns>
        string Dn { get; }

        /// <summary>
        /// Gets the subject distinguished name of this certificate.
        /// </summary>
        /// <returns>the subject distinguished name of this certificate.</returns>
        string SubjectDistinguishedName { get; }

        /// <summary>
        /// Gets the certificate chain of this certificate. The certificate chain consists of this certificate and one (or more) of its signing CAs. The chain ends with the root CA.
        /// </summary>
        /// <returns>the certificate chain of this certificate. The certificate chain consists of this certificate and one (or more) of its signing CAs. The chain ends with the root CA.</returns>
        Task<List<X509Certificate2>> CertificateChain { get; }

        /// <summary>
        /// Gets the email in this certificate or null if no email is part of this certificate.
        /// </summary>
        /// <returns>the email in this certificate or null if no email is part of this certificate.</returns>
        string EmailAddress { get; }

        /// <summary>
        /// The distribution point of the Certificate Revocation List (CRL) that this certificate must be checked against for revocation 
        /// </summary>
        /// <returns>Distribution point as a <code>String</code> of the Certificate Revocation List (CRL) that this certificate must be checked against for revocation</returns>
        string CrlDistributionPoint { get; }

        /// <summary>
        /// The distribution point of the partitioned Certificate Revocation List (CRL) that this certificate must be checked against for revocation
        /// </summary>
        /// <returns>Distribution point of the partitioned Certificate Revocation List (CRL) that this certificate must be checked against for revocation</returns>
        string PartitionedCrlDistributionPoint { get; }

        /// <summary>
        /// The distribution point of the Certificate Revocation List (CRL) that this certificate must be checked against for revocation
        /// </summary>
        /// <returns>
        /// Distribution point as a <code>CrlDistributionPoints</code> instance of the Certificate Revocation List (CRL) 
        /// that this certificate must be checked against for revocation
        /// </returns>
        CrlDistributionPoints DistributionPoints { get; }

        /// <summary>
        /// Gets the bytes of the encapsulated <code>X509Certificate</code>. Encoding is dictated by the encoding of the encapsulated X509Certificate.
        /// </summary>
        /// <returns>The bytes of the encapsulated <code>X509Certificate</code>. Encoding is dictated by the encoding of the encapsulated X509Certificate.</returns>
        Task<byte[]> GetBytes();

        /// <summary>
        /// Gets the status of the certificate @see <code>CertificateStatus</code>
        /// </summary>
        /// <returns>the status of the certificate @see <code>CertificateStatus</code></returns>
        Task<CertificateStatus> ValidityStatus();

        /// <summary>
        /// Checks if the certificate is valid on the given date.
        /// </summary>
        /// <param name="date">Date for validity check.</param>
        /// <returns>
        /// <code>CertificateStatus.Valid</code> if the certificate is valid, 
        /// <code>CertificateStatus.Expired</code> if certificate is expired, or 
        /// <code>CertificateStatus.NotYetValid if the certificate is not yet valid on the given date</code>
        /// </returns>
        Task<CertificateStatus> ValidityStatus(DateTime date);

        /// <summary>
        /// Returns true if the certificate is valid on the given date.
        /// </summary>
        /// <param name="date">date to check certificate validity</param>
        /// <returns>true if this certificate is valid on the given date.</returns>
        Task<bool> ValidOnDate(DateTime date);

        /// <summary>
        /// Gets a clone of the encapsulated <code>X509Certificate</code>
        /// </summary>
        /// <returns>A clone of the encapsulated <code>X509Certificate</code></returns>
        Task<X509Certificate2> ExportCertificate();
    }
}
