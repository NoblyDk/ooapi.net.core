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
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.validation
{
    public class HttpCrlDownloader : IHttpCrlDownloader
    {
        private readonly ILogger<HttpCrlDownloader> logger;
        private readonly TimeService _timeService;
        private readonly INemIdHttpClient _httpClient;
        private readonly IX509CrlVerifyImpl _x509CrlVerifyImpl;

        public HttpCrlDownloader(ILogger<HttpCrlDownloader> logger, TimeService timeService, INemIdHttpClient httpClient, IX509CrlVerifyImpl x509CrlVerifyImpl)
        {
            this.logger = logger;
            _timeService = timeService;
            _httpClient = httpClient;
            _x509CrlVerifyImpl = x509CrlVerifyImpl;
        }
        public virtual async Task<Crl> DownloadAsync(string location)
        {
            logger.LogDebug("DownloadAsync");
            var d = await _httpClient.Download(location);
            var crl = new Crl(d, _timeService, _x509CrlVerifyImpl);
            logger.LogDebug("Done DownloadAsync");
            return crl;
        }
    }
}
