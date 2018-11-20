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
using org.openoces.ooapi.environment;
using System.DirectoryServices.Protocols;
using org.openoces.ooapi.ldap;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace org.openoces.ooapi.validation
{
    public class LdapCrlDownloader : ILdapCrlDownloader
    {
        private readonly TimeService _timeService;
        private readonly ILdapFactory _ldapFactory;
        private readonly IX509CrlVerifyImpl _x509CrlVerifyImpl;

        public LdapCrlDownloader(TimeService timeService, ILdapFactory ldapFactory, IX509CrlVerifyImpl x509CrlVerifyImpl)
        {
            _timeService = timeService;
            _ldapFactory = ldapFactory;
            _x509CrlVerifyImpl = x509CrlVerifyImpl;
        }
        public async Task<Crl> DownloadAsync(OcesEnvironment environment, string ldapPath)
        {
            using (var connection = await _ldapFactory.CreateLdapConnection(environment))
            {
                var request = new SearchRequest(ldapPath, (string)null, SearchScope.Base, new[] { LdapFactory.CertificateRevocationListBinary});
                var response = (SearchResponse) connection.SendRequest(request);
                var bytes = (byte[])response.Entries[0].Attributes[LdapFactory.CertificateRevocationListBinary][0];

                return new Crl(bytes,_timeService, _x509CrlVerifyImpl);
            }
        }

        public async Task<X509Certificate2> DownloadCertificate(OcesEnvironment env, string ldapPath)
        {
            using (var connection = await _ldapFactory.CreateLdapConnection(env))
            {
                var request = new SearchRequest(ldapPath, (string)null, SearchScope.Base, new[] { LdapFactory.RootCertificateBinary });
                var response = (SearchResponse)connection.SendRequest(request);
                var bytes = (byte[])response.Entries[0].Attributes[LdapFactory.RootCertificateBinary][0];
                return new X509Certificate2(bytes);
            }
        }
    }
}
