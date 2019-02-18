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
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.utils;
using System;
using System.Threading.Tasks;

namespace org.openoces.ooapi.certificate
{
    public class ChainVerifier : IChainVerifier
    {
        private readonly IEnvironments _environments;
        private readonly IX509CertificatePropertyExtrator _x509CertificatePropertyExtrator;

        public ChainVerifier(IEnvironments environments, IX509CertificatePropertyExtrator x509CertificatePropertyExtrator)
        {
            _environments = environments;
            _x509CertificatePropertyExtrator = x509CertificatePropertyExtrator;
        }
        public async Task<bool> VerifyTrust(OcesCertificate certificate)
        {
            return await VerifyTrust(await certificate.ExportCertificate(), certificate.IssuingCa);
        }

        public async Task<bool> VerifyTrust(X509Certificate2 certificate, Ca signingCa)
        {
            var basicConstraints = await _x509CertificatePropertyExtrator.GetBasicConstraints(certificate);
            if (await Verify(certificate, await GetPublicKey(signingCa.Certificate)))
            {
                if (await VerifyChain(signingCa, 0))
                {
                    return await VerifyRoot(signingCa);
                }
            }
            return false;
        }

        private async Task<bool> VerifyChain(Ca ca, int pathLength)
        {
            var basicConstraints = await _x509CertificatePropertyExtrator.GetBasicConstraints(ca.Certificate);
            //check that CA certificate is in fact a CA
            if (!basicConstraints.CertificateAuthority)
            {
                return false;
            }

            //check that CA certificate must sign other certificates
            X509KeyUsageFlags flags = (await _x509CertificatePropertyExtrator.GetKeyUsage(ca.Certificate)).KeyUsages;
                        
            if((flags & (X509KeyUsageFlags.KeyCertSign))!=X509KeyUsageFlags.KeyCertSign)
            {
                return false;
            }
            
            
            // Check path length
            if (basicConstraints.HasPathLengthConstraint && basicConstraints.PathLengthConstraint < pathLength)
            {
                return false;
            }
            if (await IsSelfSigned(ca) && !ca.IsRoot)
            {
                return false;
            }
            if (ca.IsRoot)
            {
                return true;
            }
            if (ca.IssuingCa == null)
            {
                return false;
            }
            Ca signingCa = ca.IssuingCa;
            if ((await _x509CertificatePropertyExtrator.GetBasicConstraints(signingCa.Certificate)).PathLengthConstraint >= 0)
            {
                if (await Verify(ca.Certificate, await GetPublicKey(signingCa.Certificate)))
                {
                    return await VerifyChain(ca.IssuingCa, ++pathLength);
                }
            }
            return false;
        }

        private async Task<bool> IsSelfSigned(Ca ca)
        {
            return await Verify(ca.Certificate, await GetPublicKey(ca.Certificate));
        }

        private async Task<bool> VerifyRoot(Ca ca)
        {
            if (ca.IsRoot)
            {
                var certificates = await _environments.TrustedCertificates();
                foreach (var certificate in certificates)
                {
                    if (certificate.Equals(ca.Certificate))
                    {
                        return true;
                    }
                }
                return false;
            }
            return await VerifyRoot(ca.IssuingCa);
        }

        private Task<bool> Verify(X509Certificate2 certificate, AsymmetricKeyParameter publicKey)
        {
            try
            {               
                var bcCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
                bcCertificate.Verify(publicKey);
                return Task.FromResult(true);
            }
            catch (InvalidKeyException)
            {
                //ignore on purpose
            }
            catch (CertificateException)
            {
                //ignore on purpose
            }
            catch (SignatureException)
            {
                //ignore on purpose
            }
            catch
            {
                //ignore on purpose
            }
            return Task.FromResult(false);
        }

        private Task<AsymmetricKeyParameter> GetPublicKey(X509Certificate2 certificate)
        {
            return Task.FromResult(new X509CertificateParser().ReadCertificate(certificate.RawData).GetPublicKey());
        }

    }

    
}
