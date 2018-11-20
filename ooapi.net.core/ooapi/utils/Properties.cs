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
using System.Collections.Generic;
using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    /// <summary>
    /// Reads properties from App.config / Web.config.
    /// </summary>
    public class Properties : IProperties
    {
        private readonly Dictionary<string, string> _properties = new Dictionary<string, string>
      {
        // LDAP servers
        {"ldap.server.danid.OcesII_DanidEnvPreprod", "crldir.pp.certifikat.dk"},
        {"ldap.server.danid.OcesII_DanidEnvProd", "crldir.certifikat.dk"},

        // LDAP CA DNs (Root CA DNs)
        {"ldap.ca.dn.danid.OcesII_DanidEnvPreprod", "CN=TRUST2408 Systemtest VII Primary CA,O=TRUST2408,C=DK"},
        {"ldap.ca.dn.danid.OcesII_DanidEnvProd", "CN=TRUST2408 OCES Primary CA,O=TRUST2408,C=DK"},

        // PID service
        {"pid.service.url.OcesII_DanidEnvPreprod", "https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesII_DanidEnvProd", "https://pidws.certifikat.dk/pid_serviceprovider_server/pidws/"},
        
        // RID service
        {"rid.service.url.OcesII_DanidEnvPreprod", "https://ws-erhverv.pp.certifikat.dk/rid_serviceprovider_server/services/HandleSundhedsportalWSPort"},
        {"rid.service.url.OcesII_DanidEnvProd", "https://ws-erhverv.certifikat.dk/rid_serviceprovider_server/services/HandleSundhedsportalWSPort"},
        
        // RID OIO service
        {"ridoio.service.url.OcesII_DanidEnvPreprod", "https://ws-erhverv.pp.certifikat.dk/rid_serviceprovider_oio_server/v1.0.0/"},
        {"ridoio.service.url.OcesII_DanidEnvProd", "https://ws-erhverv.certifikat.dk/rid_serviceprovider_oio_server/v1.0.0/"},

        //OCES2 - policies
        {"poces.policies.prefix.danid.OcesII_DanidEnvProd", "1.2.208.169.1.1.1.1"},
        {"moces.policies.prefix.danid.OcesII_DanidEnvProd", "1.2.208.169.1.1.1.2"},
        {"voces.policies.prefix.danid.OcesII_DanidEnvProd", "1.2.208.169.1.1.1.3"},
        {"foces.policies.prefix.danid.OcesII_DanidEnvProd", "1.2.208.169.1.1.1.4"},

        {"poces.policies.prefix.danid.OcesII_DanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.1"},
        {"moces.policies.prefix.danid.OcesII_DanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.2"},
        {"voces.policies.prefix.danid.OcesII_DanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.3"},
        {"foces.policies.prefix.danid.OcesII_DanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.4"},

        // CRL cache timeouts in minutes
        {"crl.cache.timeout.ldap", "10"},
        {"crl.cache.timeout.http", "10"},

        //ICA CN to ICA HTTP download URL
        {"CN=TRUST2408 SYSTEMTEST VIII CA, O=TRUST2408, C=DK", "http://m.aia.systemtest8.trust2408.com/systemtest8-ca.cer"},
        {"CN=TRUST2408 OCES CA I, O=TRUST2408, C=DK","http://m.aia.oces-issuing01.trust2408.com/oces-issuing01-ca.cer"}
      };

        public Task<string> Get(string name)
        {
            return Task.FromResult(_properties[name]);
        }

        /// <summary>
        /// Determines whether or not the given configuration property is defined or not.
        /// </summary>
        public Task<bool> IsDefined(string name)
        {
            return Task.FromResult(_properties.ContainsKey(name));
        }

        public const int CRL_CACHE_DOWNLOAD_DEADLINE = 90; // unit in seconds 
        private const int CRL_CACHE_DEFAULT_TIMEOUT = 30;  // unit in minutes

        private int _httpCrlCacheTimeout = 0;
        private int _ldapCrlCacheTimeout = 0;


        public async Task<int> GetHttpCrlCacheTimeout()
        {
            if (_httpCrlCacheTimeout == 0)
            {
                _httpCrlCacheTimeout = await IsDefined("crl.cache.timeout.http") ? int.Parse(await Get("crl.cache.timeout.http")) : CRL_CACHE_DEFAULT_TIMEOUT;
                // timeout can not be less than two minutes
                if (_httpCrlCacheTimeout < 2)
                {
                    _httpCrlCacheTimeout = 2;
                }
            }
            return _httpCrlCacheTimeout;
        }

        public async Task<int> GetLdapCrlCacheTimeout()
        {
            if (_ldapCrlCacheTimeout == 0)
            {
                _ldapCrlCacheTimeout = await IsDefined("crl.cache.timeout.ldap") ? int.Parse(await Get("crl.cache.timeout.ldap")) : CRL_CACHE_DEFAULT_TIMEOUT;
                // timeout can not be less than two minutes
                if (_ldapCrlCacheTimeout < 2)
                {
                    _ldapCrlCacheTimeout = 2;
                }
            }
            return _ldapCrlCacheTimeout;
        }

        public Task<string> icaCNToURL(string icaCN)
        {
            return Get(icaCN);
        }
    }
}
