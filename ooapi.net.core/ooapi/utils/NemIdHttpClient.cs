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

using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    public class NemIdHttpClient : INemIdHttpClient
    {
        private readonly ILogger<NemIdHttpClient> logger;
        private readonly HttpClient httpclient;

        public NemIdHttpClient(ILogger<NemIdHttpClient> logger, HttpClient httpclient)
        {
            this.logger = logger;
            this.httpclient = httpclient;
        }
        public async Task<byte[]> Download(string location)
        {
            logger.LogDebug($"Downloading bytes from {location}");
            var response = await httpclient.GetAsync(location);
            response.EnsureSuccessStatusCode();
            var bytes = await response.Content.ReadAsByteArrayAsync();
            logger.LogDebug($"Done Downloading bytes from {location}");
            return bytes;                
        }
    }
}
