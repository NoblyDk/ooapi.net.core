using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Configuration;
using System.ServiceModel;
using org.openoces.ridService;
using System.Collections.Specialized;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ooapi.net.core.ooapi.pidservice;
using org.openoces.ooapi.utils;
using ooapi.net.core.ooapi.utils;

namespace org.openoces.ooapi.ridservice
{
    public class RidService : IRidService
    {
        private readonly ILogger<RidService> _logger;
        private readonly IEnvironmentUtil _environmentUtil;
        private readonly IClientConfiguration _clientConfiguration;
        readonly HandleSundhedsportalWSPortClient _client;

        public RidService(ILogger<RidService> logger, IEnvironmentUtil environmentUtil,IClientConfiguration clientConfiguration)
        {
            _logger = logger;
            _environmentUtil = environmentUtil;
            _clientConfiguration = clientConfiguration;
            _environmentUtil.EnableProtocolIfSupportedByPlatform(_environmentUtil.TLS12).GetAwaiter().GetResult();

            var b = new CustomHttpBinding();
            
            b.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;

            b.CloseTimeout = TimeSpan.FromMinutes(1);
            b.OpenTimeout = TimeSpan.FromMinutes(1);
            b.ReceiveTimeout  =TimeSpan.FromMinutes(10);
            b.SendTimeout = TimeSpan.FromMinutes(1);
            b.AllowCookies = false;
            b.BypassProxyOnLocal = false;
            b.MaxBufferSize = 65536;
            b.MaxBufferPoolSize = 524288;
            b.MaxReceivedMessageSize = 65536;
            b.TextEncoding = Encoding.UTF8;
            b.TransferMode = TransferMode.Buffered;
            b.UseDefaultWebProxy = true;
            b.ReaderQuotas.MaxDepth = 32;
            b.ReaderQuotas.MaxStringContentLength = 8192;
            b.ReaderQuotas.MaxArrayLength = 16384;
            b.ReaderQuotas.MaxNameTableCharCount = 16384;
            _client = new HandleSundhedsportalWSPortClient(b, new EndpointAddress(_clientConfiguration.WsUrl));

            if (!string.IsNullOrWhiteSpace(_clientConfiguration.PfxFile))
            {
                _client.ClientCredentials.ClientCertificate.Certificate = new X509Certificate2(_clientConfiguration.PfxFile, _clientConfiguration.PfxPassword);
            }
            else
            {
                _client.ClientCredentials.ClientCertificate.Certificate = new X509Certificate2(_clientConfiguration.PfxBytes);
            }
        }

        //Test RID with moces2 certificates
        public async Task Test()
        {
            await _client.testAsync();
        }

        public async Task<string> GetCpr(string rid)
        {
            return await _client.getCPRAsync(rid);
        }
    }
}