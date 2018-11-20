using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.ridservice;

namespace org.openoces.ooapi.ping
{
    public class RidAliveTester : IRidAliveTester
    {
        private readonly ILogger<RidAliveTester> _logger;
        private readonly IRidService _ridService;
        private readonly IEnvironments _environments;
        private readonly IProperties _properties;
        const string ServiceStringPrefix = "rid.service.url.";

        public RidAliveTester(ILogger<RidAliveTester> logger, IRidService ridService, IEnvironments environments, IProperties properties)
        {
            _logger = logger;
            _ridService = ridService;
            _environments = environments;
            _properties = properties;
        }
        public  async Task PingRidAsync()
        {
            try
            {
                var environments = _environments.TheTrustedEnvironments.ToList();

                if (!environments.Any())
                {
                    throw new ArgumentException("No Environment has been set");
                }

                _logger.LogDebug("Current env list {0}", environments);
                await PingRidAsync(environments);
            }
            catch (Exception e)
            {
                throw new InternalException("Exception while trying to ping rid/cpr service", e);
            }
        }

        private async Task PingRidAsync(IEnumerable<OcesEnvironment> environments)
        {
            foreach (var environment in environments)
            {
                string service = await _properties.Get(ServiceStringPrefix + environment);

                if (service == null)
                {
                    _logger.LogError("Missing property in Properties: {0}",ServiceStringPrefix + environment);
                }

                _logger.LogDebug("calling rid with service url {service}",service);
                await PingAsync(service);
            }
        }

        private async Task PingAsync(string serviceUrl)
        {

            await _ridService.Test();
        }
    }

}

