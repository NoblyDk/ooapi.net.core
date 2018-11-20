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
using System.Threading.Tasks;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.utils.ocsp;

namespace org.openoces.ooapi.utils
{
    public class OcspClient : IOcspClient
    {
        private readonly IRequestGenerator _requestGenerator;
        private readonly IRequester _requester;
        private readonly IResponseParser _responseParser;
        private readonly IRootCertificates _rootCertificates;

        public OcspClient(IRequestGenerator requestGenerator, IRequester requester, IResponseParser responseParser, IRootCertificates rootCertificates)
        {
            _requestGenerator = requestGenerator;
            _requester = requester;
            _responseParser = responseParser;
            _rootCertificates = rootCertificates;
        }
        const int TimeoutMilliseconds = 10000;
        delegate Task<bool> OcspCall(IOcesCertificate certificate);

        public Task<bool> IsValid(IOcesCertificate certificate)
        {
            OcspCall ocspCall = CheckCertificate;
            var result = ocspCall.BeginInvoke(certificate, null, null);

            bool timelyReply = result.AsyncWaitHandle.WaitOne(TimeoutMilliseconds, false);
            if (timelyReply)
            {
                return ocspCall.EndInvoke(result);
            }

            throw new TimeoutException("OCSP responder timed out");
        }

        private async Task<bool> CheckCertificate(IOcesCertificate certificate)
        {
            await _rootCertificates.GetEnvironment(certificate.IssuingCa);

            string serverUrl = certificate.OcspUrl;
          
            var reqAndId = await _requestGenerator.CreateOcspRequest(certificate);
            OcspResp resp = await _requester.SendAsync(reqAndId.Request, serverUrl);

            return await _responseParser.CertificateIsValid(reqAndId.Id, resp, certificate);
        }
    }
}