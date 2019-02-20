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

using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace org.openoces.ooapi.web
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public class Signer : ISigner
    {
        private readonly ILogger<Signer> _logger;

        public Signer(ILogger<Signer> logger)
        {
            _logger = logger;

        }

        public Task<string> GetCertificateAsync(string pfxFile, string pfxPassword)
        {
            var certificate = new X509Certificate2(pfxFile, pfxPassword);
            return GetCertificateAsBase64String(certificate);
        }
        public Task<string> GetCertificateAsync(byte[] pfxBytes, string pfxPassword)
        {
            var certificate = new X509Certificate2(pfxBytes, pfxPassword);
            return GetCertificateAsBase64String(certificate);
        }
        public Task<string> GetCertificateAsync(byte[] pfxBytes)
        {
            var certificate = new X509Certificate2(pfxBytes);
            return GetCertificateAsBase64String(certificate);
        }



        public Task<byte[]> CalculateSignatureAsync(byte[] data, string pfxFile, string pfxPassword)
        {
            try
            {
                var certificate = new X509Certificate2(pfxFile, pfxPassword);
                var csp = certificate.GetRSAPrivateKey();
                return Task.FromResult(csp.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
            catch (CryptographicException ce)
            {
                _logger.LogError(ce, "Exception");
                X509Certificate2 cert = new X509Certificate2(pfxFile, pfxPassword, X509KeyStorageFlags.Exportable);

                var rsa = cert.GetRSAPrivateKey();
                
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
        }
        public Task<byte[]> CalculateSignatureAsync(byte[] data, byte[] pfxBytes, string pfxPassword)
        {
            try
            {
                var certificate = new X509Certificate2(pfxBytes, pfxPassword);
                var csp = certificate.GetRSAPrivateKey();
                return Task.FromResult(csp.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
            catch (CryptographicException ce)
            {
                _logger.LogError(ce, "Exception");
                X509Certificate2 cert = new X509Certificate2(pfxBytes, pfxPassword, X509KeyStorageFlags.Exportable);

                var rsa = cert.GetRSAPrivateKey(); 
               
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
        }
        public Task<byte[]> CalculateSignatureAsync(byte[] data, byte[] pfxBytes)
        {
            try
            {
                var certificate = new X509Certificate2(pfxBytes);
                var csp = certificate.GetRSAPrivateKey();
                return Task.FromResult(csp.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
            catch (CryptographicException ce)
            {
                _logger.LogError(ce, "Exception");
                X509Certificate2 cert = new X509Certificate2(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);

                var rsa = cert.GetRSAPrivateKey();
               
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
        }


        private Task<string> GetCertificateAsBase64String(X509Certificate2 certificate)
        {
            byte[] encodedCertificate = certificate.Export(X509ContentType.Cert);
            String base64EncodedCertificate = Convert.ToBase64String(encodedCertificate);
            return Task.FromResult(base64EncodedCertificate.Replace("\r", "").Replace("\n", ""));
        }
    }
}