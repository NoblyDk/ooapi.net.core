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
        
        public async Task<string> GetCertificateAsync(string pfxFile, string pfxPassword)
        {
            var certificate = new X509Certificate2(pfxFile, pfxPassword);
            byte[] encodedCertificate = certificate.Export(X509ContentType.Cert);
            String base64EncodedCertificate = await Base64EncodeAsync(encodedCertificate);
            return base64EncodedCertificate.Replace("\r", "").Replace("\n", "");
        }

        public Task<byte[]> CalculateSignatureAsync(byte[] data, string pfxFile, string pfxPassword)
        {
            try
            {
                var certificate = new X509Certificate2(pfxFile, pfxPassword);
                var csp = (RSACryptoServiceProvider) certificate.PrivateKey;
                return Task.FromResult(csp.SignData(data, CryptoConfig.MapNameToOID("SHA256")));
            }
            catch (CryptographicException ce)
            {
                _logger.LogError(ce, "Exception");
                X509Certificate2 cert = new X509Certificate2(pfxFile, pfxPassword, X509KeyStorageFlags.Exportable);

                RSACryptoServiceProvider rsa = cert.PrivateKey as RSACryptoServiceProvider;
                byte[] privateKeyBlob = rsa.ExportCspBlob(true);
                RSACryptoServiceProvider rsa2 = new RSACryptoServiceProvider();
                rsa2.ImportCspBlob(privateKeyBlob);
                return Task.FromResult(rsa2.SignData(data, "SHA256"));
            }
        }

        private Task<string> Base64EncodeAsync(byte[] bytes)
        {
            return Task.FromResult(Convert.ToBase64String(bytes));
        }
    }
}