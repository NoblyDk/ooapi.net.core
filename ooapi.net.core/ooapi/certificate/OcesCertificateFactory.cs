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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.validation;
using org.openoces.serviceprovider;

namespace org.openoces.ooapi.certificate
{
    /// <summary>
    /// Factory able to create an <code>OcesCertificate</code>. 
    /// </summary>
    public class OcesCertificateFactory : IOcesCertificateFactory
    {
        private readonly IChainVerifier _chainVerifier;
        private readonly IEnvironments _environments;
        private readonly ILdapCrlDownloader _ldapCrlDownloader;
        private readonly IRootCertificates _rootCertificates;
        private readonly IX509CertificatePropertyExtrator _x509CertificatePropertyExtrator;
        private readonly IHttpClient _httpClient;
        private readonly IProperties _properties;
        private readonly IServiceProviderSetup _serviceProviderSetup;
        public OcesCertificateFactory(
            IChainVerifier chainVerifier, 
            IEnvironments environments, 
            ILdapCrlDownloader ldapCrlDownloader, 
            IRootCertificates rootCertificates,
            IX509CertificatePropertyExtrator x509CertificatePropertyExtrator,
            IHttpClient httpClient,
            IProperties properties,
            IServiceProviderSetup serviceProviderSetup)
        {
            _chainVerifier = chainVerifier;
            _environments = environments;
            _ldapCrlDownloader = ldapCrlDownloader;
            _rootCertificates = rootCertificates;
            _x509CertificatePropertyExtrator = x509CertificatePropertyExtrator;
            _httpClient = httpClient;
            _properties = properties;
            _serviceProviderSetup = serviceProviderSetup;
        }
       

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
        public async Task<OcesCertificate> Generate(List<X509Certificate2> certificates)
        {
            certificates = await SortCertificatesIssuerLast(certificates);
            await AddIssuerCertificateIfNeeded(certificates);
            await ValidateExactlyOneChainInList(certificates);
            await AppendRootIfMissing(certificates);
            X509Certificate2 endUserCertificate = certificates.First();
            Ca signingCa = await CreateCaChain(certificates);
            string subjectSerialNumber = await ExtractSubjectSerialNumber(endUserCertificate);
            OcesCertificate certificate = await SelectCertificateSubclass(subjectSerialNumber, signingCa, endUserCertificate);
            if(await _chainVerifier.VerifyTrust(certificate))
            {
                return certificate;
            }
            throw new TrustCouldNotBeVerifiedException(certificate, _environments.TheTrustedEnvironments);
        }

        private async Task AddIssuerCertificateIfNeeded(IList<X509Certificate2> certificates)
        {
            if (certificates.Count == 1)
            {
                var certificate = certificates.First();
                if (certificate.Issuer.ToUpper().Contains("TRUST2408"))
                {
                    try
                    {
                        var url = await _x509CertificatePropertyExtrator.GetCaIssuerUrl(certificate);
                        var icaCertificate = new X509Certificate2(await _httpClient.Download(url));
                        certificates.Add(icaCertificate);
                    }
                    catch (InvalidCaIssuerUrlException)
                    {
                        //certificate is missing an extension, so determine how to alternatively fetch ica certificate
                        if (_serviceProviderSetup.CurrentChecker.GetType() == typeof(FullCrlRevocationChecker) || _serviceProviderSetup.CurrentChecker.GetType() == typeof(OcspCertificateRevocationChecker))
                        {
                            String icaHttpURL = await _properties.icaCNToURL(certificate.Issuer.ToUpper());
                            var icaCertificate = new X509Certificate2(await _httpClient.Download(icaHttpURL));
                            certificates.Add(icaCertificate);
                        }
                        else
                        {
                            X509Certificate2 icaCert = await _ldapCrlDownloader.DownloadCertificate(await _environments.getOces_II_Environment(), certificate.Issuer.ToUpper());
                            certificates.Add(icaCert);
                        }
                    }
                }
            }
        }

        private Task ValidateExactlyOneChainInList(IList<X509Certificate2> certificates)
        {
            if (certificates.Count == 0)
            {
                throw new ArgumentException("Did not find any certificates");
            }

            for (var i = 0; i < certificates.Count - 1; i++)
            {
                var issuer = certificates[i].Issuer;
                var nextSubject = certificates[i + 1].Subject;
                if (issuer != nextSubject)
                {
                    throw new InvalidChainException("Certificate list holds something that is not a certificate chain");
                }
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Find all certificates that are not self-signed and has key usage "digital signature".
        /// Then sort all certificates, so that issuers are after the certificates they sign.
        /// Certificates in the list that were not part of the trust chain for the digital signatures are not retained.
        /// </summary>
        /// <returns>sorted certificates needed to verify the digital signatures from the input list</returns>
        private async Task<List<X509Certificate2>> SortCertificatesIssuerLast(IEnumerable<X509Certificate2> inputCertificates)
        {
            var result = new List<X509Certificate2>();
            var certBySubject = new Dictionary<string, X509Certificate2>();

            foreach (var certificate in inputCertificates)
            {
                certBySubject[certificate.Subject] = certificate;
                var keyUsage = await _x509CertificatePropertyExtrator.GetKeyUsage(certificate);
                if (keyUsage != null && keyUsage.KeyUsages.ToString().Contains("DigitalSignature") &&
                    !keyUsage.KeyUsages.ToString().Contains("CrlSign"))
                {
                    result.Add(certificate);
                }
            }
            for (var i = 0; i < result.Count; i++)
            {
                var certificate = result[i];
                if (!certBySubject.ContainsKey(certificate.Issuer)) continue;

                var issuer = certBySubject[result[i].Issuer];
                if (!result.Contains(issuer))
                {
                    result.Add(issuer);
                }
            }
            return result;
        }

        private Task<string> ExtractSubjectSerialNumber(X509Certificate2 endUserCertificate)
        {
            var subject = endUserCertificate.Subject;
            const string subjectSerialNumberPattern = @"((OID.2.5.4.5)|(?i:serialnumber))(\s)*=(\s)*(?<ssn>([^+,\s])*)";

            var ssn = new Regex(subjectSerialNumberPattern);
            if (!ssn.IsMatch(subject))
            {
                throw new NonOcesCertificateException("Could not find subject serial number");
            }
            var match = ssn.Match(subject);
            return Task.FromResult(match.Groups["ssn"].Value);
        }

        private async Task<OcesCertificate> SelectCertificateSubclass(String subjectSerialNumber, Ca signingCa, X509Certificate2 endUserCertificate)
        {
            var currentEnv = await GetEnvironmentForRoot(signingCa);
            if (subjectSerialNumber.StartsWith("PID:") && await MatchPocesPolicy(endUserCertificate, currentEnv))
            {
                return new PocesCertificate(endUserCertificate, signingCa);
            }
            const int lengthOfCvrXxxxxxxx = 12;
            if (subjectSerialNumber.StartsWith("CVR:") &&
                subjectSerialNumber.Substring(lengthOfCvrXxxxxxxx).StartsWith("-RID:") && await MatchMocesPolicy(endUserCertificate, currentEnv))
            {
                return new MocesCertificate(endUserCertificate, signingCa);
            }
            if (subjectSerialNumber.StartsWith("CVR:") &&
                subjectSerialNumber.Substring(lengthOfCvrXxxxxxxx).StartsWith("-UID:") && await MatchVocesPolicy(endUserCertificate, currentEnv))
            {
                return new VocesCertificate(endUserCertificate, signingCa);
            }
            if (subjectSerialNumber.StartsWith("CVR:") &&
                subjectSerialNumber.Substring(lengthOfCvrXxxxxxxx).StartsWith("-FID:") && await MatchFocesPolicy(endUserCertificate, currentEnv))
            {
                return new FocesCertificate(endUserCertificate, signingCa);
            }
            throw new NonOcesCertificateException("End user certificate is not POCES, MOCES, VOCES og FOCES");
        }

        private  async Task<bool> MatchFocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            return await MatchPolicy(endUserCertificate, await _properties.Get("foces.policies.prefix.danid." + currentEnv));
        }

        private async Task<bool> MatchVocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            return await MatchPolicy(endUserCertificate, await _properties.Get("voces.policies.prefix.danid." + currentEnv));
        }

        private async Task<bool> MatchMocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            return await MatchPolicy(endUserCertificate, await _properties.Get("moces.policies.prefix.danid." + currentEnv));
        }

        private async Task<bool> MatchPocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            if (OcesEnvironment.OcesII_DanidEnvPreprod.Equals(currentEnv))
            {
                return true; // we do not validate OCES2 preprod as external partners might have older certificates not satisfying this.
            }
            return await MatchPolicy(endUserCertificate, await _properties.Get("poces.policies.prefix.danid." + currentEnv));
        }

        private async Task<bool> MatchPolicy(X509Certificate2 endUserCertificate, string oidPrefix)
        {
            return (await _x509CertificatePropertyExtrator.GetCertificatePolicyOid(endUserCertificate)).StartsWith(oidPrefix);
        }

        private Task<OcesEnvironment> GetEnvironmentForRoot(Ca ca)
        {
            if (!ca.IsRoot)
            {
                return GetEnvironmentForRoot(ca.IssuingCa);
            }
            return _rootCertificates.GetEnvironment(ca);
        }

        private Task<Ca> CreateCaChain(IList<X509Certificate2> certificates)
        {
            Ca parent = null;
            for (int i = certificates.Count - 1; i > 0; i--)
            {
                parent = new Ca(certificates[i], parent);
            }
            return Task.FromResult(parent);
        }

        private async Task AppendRootIfMissing(IList<X509Certificate2> certificates)
        {
            if (certificates.Count == 0) return;
            var last = certificates[certificates.Count - 1];
            if (!await IsSelfSigned(last))
            {
                certificates.Add(await _rootCertificates.LookupCertificateBySubjectDn(last.IssuerName));
            }
        }

        private Task<bool> IsSelfSigned(X509Certificate2 certificate)
        {
            try
            {
                var bcCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
                bcCertificate.Verify(bcCertificate.GetPublicKey());
                return Task.FromResult(true);
            }
            catch (InvalidKeyException)
            {
            }
            catch (CertificateException)
            {
            }
            catch (SignatureException)
            {
            }
            return Task.FromResult(false);
        }
    }
}
