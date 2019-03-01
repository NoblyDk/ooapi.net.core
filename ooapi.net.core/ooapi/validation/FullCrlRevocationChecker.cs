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
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.validation
{
    public class FullCrlRevocationChecker : ICaCrlRevokedChecker
    {
        private readonly ILogger<FullCrlRevocationChecker> logger;
        private readonly ICrlDistributionPointsExtractor _crlDistributionPointsExtractor;
        private readonly IHttpCrlDownloader _httpCrlDownloader;
        

        public FullCrlRevocationChecker(ILogger<FullCrlRevocationChecker> logger, ICrlDistributionPointsExtractor crlDistributionPointsExtractor, IHttpCrlDownloader httpCrlDownloader)
        {
            this.logger = logger;
            _crlDistributionPointsExtractor = crlDistributionPointsExtractor;
            _httpCrlDownloader = httpCrlDownloader;
          
        }
       

        /// <summary>
        /// The <code>FullCrlRevocationChecker</code> instance.
        /// </summary>

        public async Task<bool> IsRevoked(IOcesCertificate certificate)
        {
            logger.LogDebug("IsRevoked");
               Crl crl = await DownloadCrl(certificate);
            var isRevoked = await crl.IsRevoked(certificate) || await IsRevoked(certificate.IssuingCa);
            logger.LogDebug("Done IsRevoked");
            return isRevoked;
        }

        public async Task<bool> IsRevoked(Ca ca)
        {
            if (ca.IsRoot)
            {
                return false;
            }

            var crl = await DownloadCrl(ca);
            return await crl.IsRevoked(ca) || await IsRevoked(ca.IssuingCa);
        }

        /// <summary>
        /// Downloads the full CRL for the given certificate.
        /// </summary>
        /// <param name="certificate">certificate to download full CRL for</param>
        /// <returns>full CRL for given certificate</returns>
        public async Task<Crl> DownloadCrl(IOcesCertificate certificate)
        {
            logger.LogDebug("DownloadCrl");
            string crlDistributionPoint = certificate.CrlDistributionPoint;
            var d = await DownloadCrl(crlDistributionPoint);
            logger.LogDebug("Done DownloadCrl");
            return d;
        }

        public async Task<Crl> DownloadCrl(Ca ca)
        {
            logger.LogDebug("DownloadCrl");
            var crlDistributionPoints =
                await _crlDistributionPointsExtractor.ExtractCrlDistributionPointsAsync(ca.Certificate);
            var d = await DownloadCrl(crlDistributionPoints.CrlDistributionPoint);
            logger.LogDebug("Done DownloadCrl");
            return d;
        }

        public async Task<Crl> DownloadCrl(string crlDistributionPoint)
        {
            logger.LogDebug("DownloadCrl");
            var crl = await _httpCrlDownloader.DownloadAsync(crlDistributionPoint);
            if (crl == null)
            {
                var e = new InvalidCrlException("The Crl could not be retrieved for url: " + crlDistributionPoint);
                logger.LogError(e, "");
                throw e;
            }

            if (await crl.IsPartial())
            {
                var e = new InvalidCrlException("Crl was downloaded successfully, but is not a partial CRL, not a full CRL" + crlDistributionPoint);
                logger.LogError(e, "");
                throw e;
            }
            logger.LogDebug("Done DownloadCrl");
            return crl;
        }
    }
}
