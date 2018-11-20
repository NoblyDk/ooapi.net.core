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
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.validation
{
    public class CachedHttpCrlDownloader : IHttpCrlDownloader
    {
        private readonly IHttpCrlDownloader _httpCrlDownloader;

        readonly ICrlCache _CrlCache;

        public CachedHttpCrlDownloader(IHttpCrlDownloader httpCrlDownloader, ICrlCache crlCache)
        {
            _httpCrlDownloader = httpCrlDownloader;
            _CrlCache = crlCache;
        }

        public async Task<Crl> DownloadAsync(string location)
        {
            if (await _CrlCache.IsValidAsync(location))
            {
                return await _CrlCache.GetCrlAsync(location);
            }

            // CRL in cache is not valid and current cache is not locked - retrieve new CRL
            return await downloadNewCrlAsync(location);
        }

        private async Task<Crl> downloadNewCrlAsync(string location)
        {
            await _CrlCache.DownloadCrlAndUpdateCacheAsync(location, new HttpDownloadableJob(location, _httpCrlDownloader));
            return await _CrlCache.GetCrlAsync(location);
        }

        public class HttpDownloadableJob : IDownloadableCrlJob
        {
            readonly string _location;
            readonly IHttpCrlDownloader _httpCrlDownloader;

            public HttpDownloadableJob(string location, IHttpCrlDownloader httpCrlDownloader)
            {
                _httpCrlDownloader = httpCrlDownloader;
                _location = location;
            }

            public async Task<Crl> DownloadAsync()
            {
                return await _httpCrlDownloader.DownloadAsync(_location);
            }
        }
    }
}
