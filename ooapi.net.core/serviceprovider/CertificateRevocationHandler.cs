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
using org.openoces.ooapi.validation;

namespace org.openoces.serviceprovider
{
    public class CertificateRevocationHandler : ICertificateRevocationHandler
    {
        private readonly IRevocationChecker _revocationChecker;
        private readonly ICaCrlRevokedChecker _caCrlRevokedChecker;

        public CertificateRevocationHandler(IRevocationChecker revocationChecker, ICaCrlRevokedChecker caCrlRevokedChecker)
        {
            _revocationChecker = revocationChecker;
            _caCrlRevokedChecker = caCrlRevokedChecker;
        }
        /// <summary>
        /// Retrieves the full CRL for the given certificate
        /// </summary>
        /// <param name="certificate">to retrieve full CRL for</param>
        /// <returns>full CRL for the given certificate</returns>
        public Task<Crl> RetrieveFullCrl(OcesCertificate certificate)
        {
            return _caCrlRevokedChecker.DownloadCrl(certificate);
        }

        /// <summary>
        /// This method verifies a certificate by calling the OCSP used in current Environment 
        /// </summary>
        /// <param name="certificate">certificate to verify</param>
        /// <returns>true if certificate is revoked else false</returns>
        public Task<bool> VerifyCertificateWithOcsp(OcesCertificate certificate)
        {
            return _revocationChecker.IsRevoked(certificate);
        }
    }
}
