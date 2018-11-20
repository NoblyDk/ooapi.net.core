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
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.pidservice;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.ping
{
    public class PidAlivetester : IPidAlivetester
    {
        private readonly ILogger<PidAlivetester> _logger;
        private readonly IPidService _pidService;
        private readonly IEnvironments _environments;
        private readonly IProperties _properties;
        const string ServiceStringPrefix = "pid.service.url.";

        public PidAlivetester(ILogger<PidAlivetester> logger, IPidService pidService, IEnvironments environments, IProperties properties)
        {
            _logger = logger;
            _pidService = pidService;
            _environments = environments;
            _properties = properties;
        }
        public async Task PingPidAsync()
        {
            try
            {
                var environments = _environments.TheTrustedEnvironments.ToList();

                if (!environments.Any())
                {
                    throw new ArgumentException("No Environment has been set");
                }

                foreach (var ocesEnvironment in environments)
                {
                    _logger.LogDebug("Current env list {0}",ocesEnvironment);
                }
            
                await PingPidAsync(environments);
            }
            catch (Exception e)
            {
                throw new InternalException("Exception while trying to ping pid/cpr service", e);
            }
        }

        private async Task PingPidAsync(IEnumerable<OcesEnvironment> environments)
        {
            foreach (var environment in environments)
            {
                string service = await _properties.Get(ServiceStringPrefix + environment);

                if (service == null)
                {
                    _logger.LogError("Missing property in ooapi.properties: {0}", ServiceStringPrefix + environment);
                }

                _logger.LogDebug("calling pid with service url {0}", service);
                await PingAsync(service);
            }
        }

        private async Task PingAsync(string serviceUrl)
        {
            await _pidService.TestAsync(serviceUrl);
        }
    }
}
