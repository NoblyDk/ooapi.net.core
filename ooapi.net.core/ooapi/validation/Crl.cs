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
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.validation
{
    /// <summary>
    /// Models a Certificate Revocation List (CRL).
    /// </summary>
    public partial class Crl
    {
        private readonly TimeService _timeService;
        private readonly IX509CrlVerifyImpl _x509CrlVerifyImpl;
        readonly X509Crl _crl;
      
        byte[] _TbsCertList; // see the class X509CrlVerifyImpl for futher info

        protected Crl(TimeService timeService, IX509CrlVerifyImpl x509CrlVerifyImpl)
        {
            _timeService = timeService;
            _x509CrlVerifyImpl = x509CrlVerifyImpl;
            // For testing purposes
        }

        public Crl(byte[] crlBytes, TimeService timeService, IX509CrlVerifyImpl x509CrlVerifyImpl)
        {
            _timeService = timeService;
            _x509CrlVerifyImpl = x509CrlVerifyImpl;
            _crl = new X509CrlParser().ReadCrl(crlBytes);
            try
            {
                _crl.GetSignature();
            }
            catch (Exception)
            {
                throw new InvalidOperationException("Error parsing CRL");
               
            }
            _TbsCertList = _crl.GetTbsCertList(); 
        }

        /// <summary>
        /// Returns <code>true</code> if the given certificate is revoked and false otherwise 
        /// </summary>
        /// <param name="certificate">certificate certificate to check for revocation</param>
        /// <returns><code>true</code> if the given certificate is revoked and false otherwise 
        /// including if this CRL has expired.</returns>
        /// <throws>InvalidOperationException if this CRL is not valid or is not signed by the certificate's issuing CA.</throws>
        public async Task<bool> IsRevoked(IOcesCertificate certificate)
        {
            try {
                await VerifyCrl(certificate.IssuingCa.Certificate);
            }
            catch (SignatureException e)
            {
                throw new InvalidSignatureException("CRL Issued by" + _crl.IssuerDN
                                                    + " does not have valid signature by certificate's issuer certificate "
                                                    + certificate.IssuingCa.Certificate.SubjectName.Name, e);
            }

            return await IsRevoked(await certificate.ExportCertificate());
        }       

        internal async Task<bool> IsRevoked(Ca ca)
        {
            if (ca.IsRoot)
            {
                throw new InvalidOperationException("Cannot check revocation for root CA");
            }

            try {
                await VerifyCrl(ca.IssuingCa.Certificate);
            }
            catch (SignatureException e)
            {
                throw new InvalidSignatureException("CRL Issued by" + _crl.IssuerDN
                                                    + " does not have valid signature by ca's issuer certificate "
                                                    + ca.IssuingCa.Certificate.SubjectName.Name, e);
            }
            return await IsRevoked(ca.Certificate);
        }

        private async Task<bool> IsRevoked(X509Certificate2 certificate)
        {
            await AssertCrlCurrentlyValid();
            await AssertCrlIssuedByCertificateIssuer(certificate);

            var bcCert = new X509CertificateParser().ReadCertificate(certificate.RawData);
            return _crl.IsRevoked(bcCert);
        }

        private Task AssertCrlIssuedByCertificateIssuer(X509Certificate2 certificate)
        {
            var certiticateIssuerName = new X509Name(certificate.IssuerName.Name);
            if (!_crl.IssuerDN.Equivalent(certiticateIssuerName))
            {
                throw new InvalidOperationException("CRL is not issued by the certificate's issuing CA. CRL is issued by: "
                    + _crl.IssuerDN + ", certificate is issued by: " + certiticateIssuerName);
            }

            return Task.CompletedTask;
        }

        public async Task<bool> IsCrlExpired()
        {
            await AssertCrlNotBeforeValidity();
            try
            {
                await AssertCrlNotExpired();
            }
            catch (InvalidOperationException)
            {
                return true;
            }

            return false;
        }


        private async Task AssertCrlCurrentlyValid()
        {
            await AssertCrlNotExpired();
            await AssertCrlNotBeforeValidity();
        }

        private async Task AssertCrlNotBeforeValidity()
        {
            DateTime now = await _timeService.GetUniversalTime();
            if (now < _crl.ThisUpdate)
            {
                throw new CrlNotYetValidException("CRL is not yet valid, crl is valid from " + _crl.ThisUpdate);
            }
        }

        private async Task AssertCrlNotExpired()
        {
            DateTime now = await _timeService.GetUniversalTime();
            if (now > _crl.NextUpdate.Value)
            {
                throw new CrlExpiredException("CRL is expired, crl is valid to " + _crl.NextUpdate);
            }
        }

        public async Task<bool> IsValid()
        {
            var isExpired = await IsCrlExpired();
            return !isExpired;
        }

        private async Task VerifyCrl(X509Certificate2 certificate)
        {
            var bcIssuingCaCert = new X509CertificateParser().ReadCertificate(certificate.RawData);
            try
            {
                 _crl.Verify(bcIssuingCaCert.GetPublicKey());
                await _x509CrlVerifyImpl.Verify(bcIssuingCaCert.GetPublicKey(), _crl, _TbsCertList); 
            }
            catch (SignatureException e)
            {
                throw new InvalidSignatureException("CRL Issued by" + _crl.IssuerDN
                                                    + " does not have valid signature by certificate's issuer certificate "
                                                    + certificate.IssuerName, e);
            }
        }

        public virtual Task<bool> IsPartial()
        {
            return Task.FromResult(_crl.GetExtensionValue(new DerObjectIdentifier(ObjectIdentifiers.PartialDistributionPointOid)) != null);
        }

        public async Task<bool> IsCorrectPartialCrl(string crlLdapUrl)
        {
            string distributionPointInfo = Encoding.ASCII.GetString(_crl.GetExtensionValue(new DerObjectIdentifier(ObjectIdentifiers.PartialDistributionPointOid)).GetDerEncoded()).ToLower();
            string partialCrlNumber = await GetCrlNumberFromPartitionCrlUrl(crlLdapUrl);
            return distributionPointInfo.Contains(partialCrlNumber);
        }

        private Task<string> GetCrlNumberFromPartitionCrlUrl(string crlUrl)
        {
            string[] crlUrlSplit = crlUrl.ToLower().Split(Convert.ToChar(","));
            if (crlUrlSplit == null || crlUrlSplit.Length < 1) throw new InvalidCrlException("the crl url is malformed" + crlUrl);
            string crlNumber = crlUrlSplit[0];
            if (crlNumber.Length < "cn=crl".Length) throw new InvalidCrlException("The DN is not of expected format." + crlUrl);
            return Task.FromResult(crlNumber.Substring("cn=".Length));
        }

    }
}