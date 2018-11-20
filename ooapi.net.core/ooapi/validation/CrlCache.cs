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
using System.Threading;
using System.Threading.Tasks;

namespace org.openoces.ooapi.validation
{
    public class CrlCache : ICrlCache
    {
        readonly Dictionary<String, CrlCacheElement> _crls = new Dictionary<string, CrlCacheElement>();
        readonly int _timeout;

        /// <param name="timeout">The timeout in minutes of cached elements</param>
        public CrlCache(int timeout)
        {
            _timeout = timeout;
        }

        public async Task<Crl> GetCrlAsync(string key)
        {
            return await _crls[key].GetValueAsync();
        }
        SemaphoreSlim mutex = new SemaphoreSlim(1);
        public async Task DownloadCrlAndUpdateCacheAsync(string key, IDownloadableCrlJob job)
        {
            await mutex.WaitAsync();
            try
            {
                if (await IsValidAsync(key))
                {
                    return;
                }
                else
                {
                    await UpdateCrlCacheAsync(key, await job.DownloadAsync());
                }
            }
            finally
            {
                mutex.Release();
            }
        }

        private Task UpdateCrlCacheAsync(string key, Crl crl)
        {
            _crls[key] = new CrlCacheElement(crl);
            return Task.CompletedTask;
        }

        public async Task<bool> IsValidAsync(string key)
        {
            _crls.TryGetValue(key, out var cacheElement);
            if (cacheElement == null) return false;
            var value = await cacheElement.GetValueAsync();
            if (!await value.IsValid()) return false;
            var creationTime = await cacheElement.GetCreationTimeAsync();
            var expirationTime = creationTime.AddMinutes(_timeout);
            return expirationTime > DateTime.Now;

        }

        public async Task<bool> CheckOnlyIfCrlIsValidAsync(string key)
        {
            _crls.TryGetValue(key, out var cacheElement);
            if (cacheElement == null) return false;
            var value = await cacheElement.GetValueAsync();

            return await value.IsValid();

        }
    }

    public class CrlCacheElement
    {
        private readonly Crl _crl;
        private readonly DateTime _creationTime;

        public CrlCacheElement(Crl crl)
        {
            _crl = crl;
            _creationTime = DateTime.Now;
        }

        public Task<DateTime> GetCreationTimeAsync()
        {
            return Task.FromResult(_creationTime);
        }

        public Task<Crl> GetValueAsync()
        {
            return Task.FromResult(_crl);
        }
    }
}
