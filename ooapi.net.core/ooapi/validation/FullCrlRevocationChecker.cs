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
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.validation
{
    public class FullCrlRevocationChecker : ICaCrlRevokedChecker
    {
        private readonly ICrlDistributionPointsExtractor _crlDistributionPointsExtractor;
        private readonly IHttpCrlDownloader _httpCrlDownloader;
        

        public FullCrlRevocationChecker(ICrlDistributionPointsExtractor crlDistributionPointsExtractor, IHttpCrlDownloader httpCrlDownloader)
        {
            _crlDistributionPointsExtractor = crlDistributionPointsExtractor;
            _httpCrlDownloader = httpCrlDownloader;
          
        }
       

        /// <summary>
        /// The <code>FullCrlRevocationChecker</code> instance.
        /// </summary>

        public async Task<bool> IsRevoked(IOcesCertificate certificate)
        {
            Crl crl = await DownloadCrl(certificate);
            return await crl.IsRevoked(certificate) || await IsRevoked(certificate.IssuingCa);
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
            string crlDistributionPoint = certificate.CrlDistributionPoint;
            return await DownloadCrl(crlDistributionPoint);
        }

        public async Task<Crl> DownloadCrl(Ca ca)
        {
            var crlDistributionPoints =
                await _crlDistributionPointsExtractor.ExtractCrlDistributionPointsAsync(ca.Certificate);
           return await DownloadCrl(crlDistributionPoints.CrlDistributionPoint);
        }

        public async Task<Crl> DownloadCrl(string crlDistributionPoint)
        {
            var crl = await _httpCrlDownloader.DownloadAsync(crlDistributionPoint);
            if (crl == null)
            {
                throw new InvalidCrlException("The Crl could not be retrieved for url: " + crlDistributionPoint);
            }

            if (await crl.IsPartial())
            {
                throw new InvalidCrlException("Crl was downloaded successfully, but is not a partial CRL, not a full CRL" + crlDistributionPoint);
            }
            return crl;
        }
    }
}
