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
using org.openoces.ooapi.pidservice.impl;
using org.openoces.ooapi.utils;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ooapi.net.core.ooapi.pidservice;
using ooapi.net.core.ooapi.utils;

namespace org.openoces.ooapi.pidservice
{


    public class PidService : IPidService
    {

        private readonly ILogger<PidService> _logger;
        private readonly IClientConfiguration _clientConfiguration;

        pidwsdocPortClient _client;

        public PidService(ILogger<PidService> logger, IEnvironmentUtil environmentUtil, IClientConfiguration clientConfiguration)
        {
            environmentUtil.EnableProtocolIfSupportedByPlatform(environmentUtil.TLS12).GetAwaiter().GetResult();

            _logger = logger;
            _clientConfiguration = clientConfiguration;
          

            _logger.LogDebug("Creating PID service for: {0}", _clientConfiguration.WsUrl);


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
            b.TransferMode = TransferMode.StreamedRequest;
            b.UseDefaultWebProxy = true;
            b.ReaderQuotas.MaxDepth = 32;
            b.ReaderQuotas.MaxStringContentLength = 8192;
            b.ReaderQuotas.MaxArrayLength = 16384;
            b.ReaderQuotas.MaxNameTableCharCount = 16384;

            var e = new EndpointAddress(_clientConfiguration.WsUrl);
         
            _client = new pidwsdocPortClient(b, e);

            if (!string.IsNullOrWhiteSpace(_clientConfiguration.PfxFile))
            {
                _client.ClientCredentials.ClientCertificate.Certificate = new X509Certificate2(_clientConfiguration.PfxFile, _clientConfiguration.PfxPassword);
            }
            else
            {
                _client.ClientCredentials.ClientCertificate.Certificate = new X509Certificate2(_clientConfiguration.PfxBytes);
            }


        }
        public async Task TestAsync()
        {
            await _client.testAsync();
        }
        public async Task TestAsync(string serviceUrl)
        {
            //var content = new StringContent("soapString", Encoding.UTF8, "text/xml");
            //var _clientHandler = new HttpClientHandler();
            //_clientHandler.ClientCertificates.Add(new X509Certificate2(_clientConfiguration.PfxFile, _clientConfiguration.PfxPassword));
            //_clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
            //using (var httpClient = new System.Net.Http.HttpClient(_clientHandler)
            //{
                
            //})
            //{
            //    var response = await httpClient.PostAsync("https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidxml/", content);
            //    var code = response.StatusCode;
            //    var result = await response.Content.ReadAsStringAsync();
            //}

            //_client.Endpoint.Address = new EndpointAddress(serviceUrl);
            //_client.Endpoint.EndpointBehaviors.Add(new SimpleEndpointBehavior());
            await _client.testAsync();
            //_client.Endpoint.Address = new EndpointAddress(_clientConfiguration.WsUrl);
            
        }
       
        public Task<int> TestConnectionAsync(int value)
        {
            return _client.testConnectionAsync(value);
        }

        public async Task<string> LookupCprAsync(string pid, string callerSpid)
        {
            var reply = await CallAsync(callerSpid, pid, null);
            _logger.LogTrace("CPR lookup on PID {0} from caller SPID {1} : result was CPR {2}", pid, callerSpid, reply?.CPR);
            return reply?.CPR;
        }

        public async Task<bool> MatchAsync(string cpr, string pid, string callerSpid)
        {
            var reply = await CallAsync(callerSpid, pid, cpr);
            _logger.LogTrace("Match on PID {0} and CPR {1} from caller SPID {2} : result was {3}", pid, cpr, callerSpid, reply?.statusCode == "0" );
            switch (reply?.statusCode)
            {
                case "0":
                    return true;
                case "1":
                    return false;
                default:
                    return false; // her forventer vi aldrig at lande
            }
        }

        private async Task<PIDReply> CallAsync(string callerSpid, string pid, string cpr)
        {
            var requestsList = await CreatePidRequestListAsync(callerSpid, pid, cpr);
            var reply = await CallAsync(requestsList);

            await HandleErrorStatusesAsync(reply);
            return reply;
        }

        private async Task<PIDReply> CallAsync(List<PIDRequest> requestsList)
        {
            var response = await _client.pidAsync(requestsList);
            return response?.Body?.result?.FirstOrDefault();
        }

        private async Task<List<PIDRequest>> CreatePidRequestListAsync(string callerSpid, string pid, string cpr)
        {
            return new List<PIDRequest>()
            {
                await CreatePidRequest(callerSpid, pid, cpr)
            };
        }

        private Task<PIDRequest> CreatePidRequest(string callerSpid, string pid, string cpr)
        {
            return Task.FromResult(new PIDRequest { PID = pid, CPR = cpr, serviceId = callerSpid });
        }

        private Task HandleErrorStatusesAsync(PIDReply reply)
        {
            int statusCode = int.Parse(reply.statusCode);
            var statusTextUK = reply.statusTextUK;
            var statusTextDK = reply.statusTextDK;


            if (statusCode == 0 || statusCode == 1)
            {
                return Task.CompletedTask;
            }
            if (statusCode == CallerNotAuthorizedForCprLookupException.ErrorCode)
            {
                throw new CallerNotAuthorizedForCprLookupException(statusTextUK, statusTextDK);
            }
            if (statusCode == CallerNotAuthorizedException.ErrorCode)
            {
                throw new CallerNotAuthorizedException(statusTextUK, statusTextDK);
            }
            throw new PidServiceException(statusCode, statusTextUK, statusTextDK);
        }
    }

   
}
