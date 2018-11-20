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
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.ldap
{
    public class LdapFactory : ILdapFactory
    {
        private readonly IProperties _properties;
        public const string CertificateRevocationListBinary = "certificateRevocationList;binary";
        public const string RootCertificateBinary = "cACertificate;binary";

        public LdapFactory(IProperties properties)
        {
            _properties = properties;
        }
        public async Task<LdapConnection> CreateLdapConnection(OcesEnvironment environment)
        {
            var ldapServerName = await _properties.Get("ldap.server.danid." + environment);
            var ldapConnection = new LdapConnection(ldapServerName) { AuthType = AuthType.Anonymous };
            ldapConnection.SessionOptions.ProtocolVersion = 3;
            return ldapConnection;
        }
    }
}
