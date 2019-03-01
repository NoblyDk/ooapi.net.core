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
using Microsoft.Extensions.Logging;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.signatures
{
    public class OpensignSignatureFactory : IOpensignSignatureFactory
    {
        private readonly ILogger<OpensignSignatureFactory> logger;
        private readonly IOcesCertificateFactory _ocesCertificateFactory;
        private readonly IXmlUtil _xmlUtil;

        public OpensignSignatureFactory(ILogger<OpensignSignatureFactory> logger, IOcesCertificateFactory ocesCertificateFactory, IXmlUtil xmlUtil)
        {
            this.logger = logger;
            _ocesCertificateFactory = ocesCertificateFactory;
            _xmlUtil = xmlUtil;
        }
        public async Task<OpensignAbstractSignature> GenerateOpensignSignature(string xmlDoc)
        {
            logger.LogDebug("GenerateOpensignSignature");
            if (xmlDoc == null)
            {
                throw new NullReferenceException("xmlDoc cannot be null");
            }
            if (xmlDoc.Length < 10 && !xmlDoc.StartsWith("<")) throw new Oces2ErrorCode(xmlDoc);
            var xml = await _xmlUtil.LoadXml(xmlDoc);
            var signature = new OpensignSignature(xml, _ocesCertificateFactory);
            var actionProperty = signature.SignatureProperties["action"];
            if (actionProperty != null && ("bG9nb24=".Equals(actionProperty.Value) || "logon".Equals(actionProperty.Value.ToLower())))
            {
                return new OpenlogonSignature(xml, _ocesCertificateFactory);
            }
            logger.LogDebug("Done GenerateOpensignSignature");
            return signature;
        }
    }
}
