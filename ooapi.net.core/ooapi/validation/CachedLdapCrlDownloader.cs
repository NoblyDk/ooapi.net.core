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
using org.openoces.ooapi.environment;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.validation
{
    public class CachedLdapCrlDownloader : ICachedLdapCrlDownloader
    {
        private readonly ILdapCrlDownloader _ldapCrlDownloader;
        readonly ICrlCache _CrlCache;

        public CachedLdapCrlDownloader(ILdapCrlDownloader ldapCrlDownloader, ICrlCache crlCache)
        {
            _ldapCrlDownloader = ldapCrlDownloader;
            _CrlCache = crlCache;
        }

        public async Task<Crl> Download(OcesEnvironment environment, String ldapPath)
        {
            if (await _CrlCache.IsValidAsync(ldapPath))
            {
                // cache is containing valid element just use it
                return await _CrlCache.GetCrlAsync(ldapPath);
            }

            // CRL in cache is not valid and it IS NOT locked - retrieve new CRL
            return await DownloadNewCrl(environment, ldapPath);
        }

        private async Task<Crl> DownloadNewCrl(OcesEnvironment environment, String ldapPath)
        {
            await _CrlCache.DownloadCrlAndUpdateCacheAsync(ldapPath, new LdapDownloadableJob(_ldapCrlDownloader, environment, ldapPath));
            return await _CrlCache.GetCrlAsync(ldapPath);
        }

        public class LdapDownloadableJob : IDownloadableCrlJob
        {
            private readonly ILdapCrlDownloader _ldapCrlDownloader;
            private readonly OcesEnvironment _environment;
            private readonly string _ldapPath;

            public LdapDownloadableJob(ILdapCrlDownloader ldapCrlDownloader, OcesEnvironment environment, String ldapPath)
            {
                _ldapCrlDownloader = ldapCrlDownloader;
                _environment = environment;
                _ldapPath = ldapPath;
            }

            public async Task<Crl> DownloadAsync()
            {
                return await _ldapCrlDownloader.DownloadAsync(_environment, _ldapPath);
            }
        }
    }
}
