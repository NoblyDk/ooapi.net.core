/*
    Copyright 2010 DanID

    This file is part of OpenOcesAPI.

    OpenOcesAPI is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    OpenOcesAPI is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with OpenOcesAPI; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


    Note to developers:
    If you add code to this file, please take a minute to add an additional
    @author statement below.
*/
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.validation;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.certificate
{
    /// <summary>
    /// Abstract super class for all types of OCES certificates.
    /// </summary>
    public abstract class OcesCertificate : IOcesCertificate
    {
        protected const int LengthOfCvrXxxxxxxx = 12;
        protected const int LengthOfCvr = 4; //"CVR:".Length;
        protected const int LengthOfCvrNumber = 8;
        protected X509Certificate2 Certificate;
        public string SubjectSerialNumber { get; private set;}

        /// <summary>
        /// Gets the signing Certificate Authority (CA) parent relation of this certificate
        /// </summary>
        public Ca IssuingCa { get; private set; }

        /// <summary>
        /// Creates a OcesCertificate.
        /// </summary>
        /// <param name="certificate"><code>X509Certificate</code> to encapsulate</param>
        /// <param name="issuingCa">parent relation to its issuing CA</param>
        protected OcesCertificate(X509Certificate2 certificate, Ca issuingCa)
        {
            Certificate = certificate;
            IssuingCa = issuingCa;
            SubjectSerialNumber = ExtractSubjectSerialNumber(certificate).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets the bytes of the encapsulated <code>X509Certificate</code>. Encoding is dictated by the encoding of the encapsulated X509Certificate.
        /// </summary>
        /// <returns>The bytes of the encapsulated <code>X509Certificate</code>. Encoding is dictated by the encoding of the encapsulated X509Certificate.</returns>
        public Task<byte[]> GetBytes()
        {
            return Task.FromResult(Certificate.Export(X509ContentType.Cert));
        }

        /// <summary>
        /// Gets the subject CN (common name) of the certificate.
        /// </summary>
        /// <returns>The subject CN (common name) of the certificate.</returns>
        public string SubjectCn
        {
            get
            {
                return new X509CertificatePropertyExtrator().GetSubjectCommonName(Certificate).GetAwaiter().GetResult();
            }
        }

        private Task<string> ExtractSubjectSerialNumber(X509Certificate2 endUserCertificate)
        {
            string subject = endUserCertificate.Subject;
            const string subjectSerialNumberPattern = @"((OID.2.5.4.5)|(s|S)(e|E)(r|R)(i|I)(a|A)(l|L)(n|N)(u|U)(m|M)(b|B)(e|E)(r|R))(\s)*=(\s)*(?<ssn>([^+,\s])*)";

            var ssn = new Regex(subjectSerialNumberPattern);
            if (!ssn.IsMatch(subject))
            {
                throw new NonOcesCertificateException("could not find subject serial number");
            }
            Match match = ssn.Match(subject);
            return Task.FromResult(match.Groups["ssn"].Value);
        }

            /// <summary>
        /// Gets the start date of the validity period.
        /// </summary>
        /// <returns>the start date of the validity period.</returns>
        public DateTime NotBefore
        {
            get { return Certificate.NotBefore; }
        }

        /// <summary>
        /// Gets the end date of the validity period.
        /// </summary>
        /// <returns>the end date of the validity period.</returns>
        public DateTime NotAfter
        {
            get { return Certificate.NotAfter; }
        }

        /// <summary>
        /// Gets the status of the certificate @see <code>CertificateStatus</code>
        /// </summary>
        /// <returns>the status of the certificate @see <code>CertificateStatus</code></returns>
        public Task<CertificateStatus> ValidityStatus()
        {
            return ValidityStatus(DateTime.Now);
        }

        /// <summary>
        /// Checks if the certificate is valid on the given date.
        /// </summary>
        /// <param name="date">Date for validity check.</param>
        /// <returns>
        /// <code>CertificateStatus.Valid</code> if the certificate is valid, 
        /// <code>CertificateStatus.Expired</code> if certificate is expired, or 
        /// <code>CertificateStatus.NotYetValid if the certificate is not yet valid on the given date</code>
        /// </returns>
        public Task<CertificateStatus> ValidityStatus(DateTime date)
        {
            if (Certificate.NotBefore > date)
            {
                return Task.FromResult(CertificateStatus.NotYetValid);
            }
            if (Certificate.NotAfter < date)
            {
                return Task.FromResult(CertificateStatus.Expired);
            }
            return Task.FromResult(CertificateStatus.Valid);
        }

        /// <summary>
        /// Returns true if the certificate is valid on the given date.
        /// </summary>
        /// <param name="date">date to check certificate validity</param>
        /// <returns>true if this certificate is valid on the given date.</returns>
        public async Task<bool> ValidOnDate(DateTime date)
        {
            return await ValidityStatus(date) == CertificateStatus.Valid;
        }

        /// <summary>
        /// Gets the serial number of certificate. The serial number is unique for all certificates issued by a specific CA. 
        /// </summary>
        /// <returns>
        /// serial number of certificate. The serial number is unique for all certificates issued by a specific CA. 
        /// </returns>
        public string SerialNumber
        {
            get { return Certificate.GetSerialNumberString(); }
        }

        /// <summary>
        /// Gets the OCSP URL of the certificate
        /// </summary>
        /// <returns>the OCSP URL of the certificate</returns>
        public String OcspUrl
        {
            get { return new X509CertificatePropertyExtrator().GetOcspUrl(Certificate).GetAwaiter().GetResult(); }
        }
        
        /// <summary>
        /// Gets the caIssuer URL of the certificate
        /// </summary>
        /// <returns>the caIssuer URL of the certificate</returns>
        /// <throws>InvalidCaIssuerUrlException in case that no ca issuer url specified in the certificate.</throws>
        public String CaIssuerUrl
        {
            get { return new X509CertificatePropertyExtrator().GetCaIssuerUrl(Certificate).GetAwaiter().GetResult(); }
        }

        /// <summary>
        /// Gets the distinguished name of the issuer CA.
        /// </summary>
        /// <returns>distinguished name of the issuer CA.</returns>
        public string IssuerDn
        {
            get { return Certificate.IssuerName.Name; }
        }

        /// <summary>
        /// Gets the distinguished name of this certificate.
        /// </summary>
        /// <returns>the distinguished name of this certificate.</returns>
        public string Dn
        {
            get { return Certificate.Subject; }
        }

        /// <summary>
        /// Gets the subject distinguished name of this certificate.
        /// </summary>
        /// <returns>the subject distinguished name of this certificate.</returns>
        public string SubjectDistinguishedName
        {
            get { return Certificate.SubjectName.Name; }
        }

        /// <summary>
        /// Gets the certificate chain of this certificate. The certificate chain consists of this certificate and one (or more) of its signing CAs. The chain ends with the root CA.
        /// </summary>
        /// <returns>the certificate chain of this certificate. The certificate chain consists of this certificate and one (or more) of its signing CAs. The chain ends with the root CA.</returns>
        public Task<List<X509Certificate2>> CertificateChain
        {
            get
            {
                var chain = new List<X509Certificate2> {Certificate};

                Ca parent = IssuingCa;
                while (parent != null)
                {
                    chain.Add(parent.Certificate);
                    parent = parent.IssuingCa;
                }
                return Task.FromResult(chain);
            }
        }

        /// <summary>
        /// Gets the email in this certificate or null if no email is part of this certificate.
        /// </summary>
        /// <returns>the email in this certificate or null if no email is part of this certificate.</returns>
        public string EmailAddress
        {
            get { return new X509CertificatePropertyExtrator().GetEmailAddress(Certificate).GetAwaiter().GetResult(); }
        }

     
        /// <summary>
        /// Gets a specific element of the subject DN
        /// </summary>
        /// <param name="element">element <code>Name</code> of element to return value of</param>
        /// <returns>Specific element of the subject DN</returns>
        protected string GetElementInX509Name(String element)
        {
            return new X509CertificatePropertyExtrator().GetElementInX509Name(Certificate, element).GetAwaiter().GetResult();
        } 

        /// <summary>
        /// The distribution point of the Certificate Revocation List (CRL) that this certificate must be checked against for revocation 
        /// </summary>
        /// <returns>Distribution point as a <code>String</code> of the Certificate Revocation List (CRL) that this certificate must be checked against for revocation</returns>
        public string CrlDistributionPoint
        {
            get { return DistributionPoints.CrlDistributionPoint; }
        }

        /// <summary>
        /// The distribution point of the partitioned Certificate Revocation List (CRL) that this certificate must be checked against for revocation
        /// </summary>
        /// <returns>Distribution point of the partitioned Certificate Revocation List (CRL) that this certificate must be checked against for revocation</returns>
        public string PartitionedCrlDistributionPoint
        {
            get { return DistributionPoints.PartitionedCrlDistributionPoint; }
        }

        /// <summary>
        /// The distribution point of the Certificate Revocation List (CRL) that this certificate must be checked against for revocation
        /// </summary>
        /// <returns>
        /// Distribution point as a <code>CrlDistributionPoints</code> instance of the Certificate Revocation List (CRL) 
        /// that this certificate must be checked against for revocation
        /// </returns>
        public CrlDistributionPoints DistributionPoints
        {
            get { return new CrlDistributionPointsExtractor().ExtractCrlDistributionPointsAsync(Certificate).GetAwaiter().GetResult(); }
        }


        /// <summary>
        /// Gets a clone of the encapsulated <code>X509Certificate</code>
        /// </summary>
        /// <returns>A clone of the encapsulated <code>X509Certificate</code></returns>
        public Task<X509Certificate2> ExportCertificate()
        {
            return Task.FromResult(Certificate);
        }
    }
}
