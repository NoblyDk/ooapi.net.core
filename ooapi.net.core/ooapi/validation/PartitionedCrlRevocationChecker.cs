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
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.validation
{
    /// <summary>
    /// <code>RevocationChecker</code> based on a partitioned CRL.
    /// </summary>
    public class PartitionedCrlRevocationChecker : IRevocationChecker
    {
        private readonly IRootCertificates _rootCertificates;
        private readonly ICachedLdapCrlDownloader _cachedLdapCrlDownloader;
        private readonly ICrlDistributionPointsExtractor _crlDistributionPointsExtractor;

        PartitionedCrlRevocationChecker(IRootCertificates rootCertificates, ICachedLdapCrlDownloader cachedLdapCrlDownloader, ICrlDistributionPointsExtractor crlDistributionPointsExtractor)
        {
            _rootCertificates = rootCertificates;
            _cachedLdapCrlDownloader = cachedLdapCrlDownloader;
            _crlDistributionPointsExtractor = crlDistributionPointsExtractor;
        }


        /// <summary>
        /// The partitioned CRL to check for revocation is retrieved using LDAP.
        /// </summary>
        public async Task<bool> IsRevoked(IOcesCertificate certificate)
        {
            string ldapPath = certificate.PartitionedCrlDistributionPoint;
            OcesEnvironment environment = await _rootCertificates.GetEnvironment(certificate.IssuingCa);

            Crl crl = await _cachedLdapCrlDownloader.Download(environment, ldapPath);

            if (!await crl.IsPartial())
            {
                throw new InvalidCrlException("Crl was downloaded successfully, but is not a partial CRL:" + ldapPath);
            }
            if (!await crl.IsCorrectPartialCrl(ldapPath))
            {
                throw new InvalidCrlException("Crl was downloaded successfully, but is not the correct partitioned crl:" + ldapPath);
            }


            return await crl.IsRevoked(certificate) || await IsRevoked(certificate.IssuingCa);
        }

        public async Task<bool> IsRevoked(Ca ca)
        {
            if (ca.IsRoot)
            {
                return false;
            }
            OcesEnvironment environment = await _rootCertificates.GetEnvironment(ca.IssuingCa);
            return await (await DownloadCrl(ca, environment)).IsRevoked(ca) || await IsRevoked(ca.IssuingCa);
        }

        private async Task<Crl> DownloadCrl(Ca ca, OcesEnvironment environment)
        {
            var crlDistributionPoint = await _crlDistributionPointsExtractor.ExtractCrlDistributionPointsAsync(ca.Certificate);
            return await _cachedLdapCrlDownloader.Download(environment, crlDistributionPoint.PartitionedCrlDistributionPoint);
        }
    }
}
