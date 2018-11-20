using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace org.openoces.ooapi.utils
{
    public class EnvironmentUtil : IEnvironmentUtil
    {
        private readonly ILogger<EnvironmentUtil> _logger;

        public EnvironmentUtil(ILogger<EnvironmentUtil> logger)
        {
            _logger = logger;
        }
       
        /**
         * Flags provided protocol as enabled, if it is supported by the runtime environment.
         */
        public SecurityProtocolType TLS12 => (SecurityProtocolType) 3072;

        public  async Task EnableProtocolIfSupportedByPlatform(SecurityProtocolType protocol)
        {
            var isProtocolEnabled = await IsProtocolEnabled(protocol);
            if (!isProtocolEnabled)
            {
                if (await IsProtocolSupported(protocol))
                {
                    _logger.LogDebug("Platform supports protocol with hash {0}, but it is not on the list of enabled protocols. Adding to the list now.", protocol.GetHashCode());
                    await EnableProtocol(TLS12);
                }
                else
                {
                    _logger.LogDebug("Platform does not support protocol with hash {0}. Can not enable it", protocol.GetHashCode());
                }
            }
        }

        public Task<bool> IsProtocolSupported(SecurityProtocolType protocol)
        {
            foreach (SecurityProtocolType p in Enum.GetValues(typeof(SecurityProtocolType)))
            {
                if (p == protocol)
                {
                    return Task.FromResult(true);
                }
            }
            return Task.FromResult(false);
        }

        public Task<bool> IsProtocolEnabled(SecurityProtocolType protocol)
        {
            return Task.FromResult(ServicePointManager.SecurityProtocol.HasFlag(protocol));
        }

        public Task DissableProtocol(SecurityProtocolType protocol)
        {
            ServicePointManager.SecurityProtocol &= ~protocol;
            return Task.CompletedTask;
        }

        /**
         * Flags provided protocol as enabled without verifying first, if this protocol is supported by the runtime environment.
         */
        public Task EnableProtocol(SecurityProtocolType protocol)
        {
            ServicePointManager.SecurityProtocol |= protocol;
            return Task.CompletedTask;
        }
    }

}
