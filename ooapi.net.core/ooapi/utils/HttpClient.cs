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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace org.openoces.ooapi.utils
{
    public class HttpClient : IHttpClient
    {
        public Task<byte[]> Download(string location)
        {
            if (location == null)
            {
                throw new ArgumentException("location is null");
            }
            if (!location.ToLower().StartsWith("http://"))
            {
                throw new ArgumentException("location excepted to have the prefix 'http://'");
            }
            var uri = new Uri(location);
            return ReadBytesFromUri(uri);
        }

        public async Task<byte[]> ReadBytesFromUri(Uri uri)
        {
            WebRequest request = WebRequest.Create(uri);
            using (var response = await request.GetResponseAsync())
            {
                using (var responseStream = response.GetResponseStream())
                {
                    return await ReadBytesFromStream(responseStream);
                }
            }
        }

        public Task<byte[]> ReadBytesFromStream(Stream responseStream)
        {
            var bytes = new List<byte>();
            int nextByte;
            for (int i = 0; (nextByte = responseStream.ReadByte()) != -1; i++)
            {
                bytes.Add((byte)nextByte);
            }
            return Task.FromResult(bytes.ToArray());
        }
    }
}
