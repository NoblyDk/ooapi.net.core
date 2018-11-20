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
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.validation
{
    public class XmlDsigParser
    {
        private readonly IXmlUtil _xmlUtil;

        public XmlDsigParser(IXmlUtil xmlUtil)
        {
            _xmlUtil = xmlUtil;
        }
        /// <summary>
        /// Creates a chain of X509Certificates given the provided XML-DSig.
        /// </summary>
        /// <param name="xmlDoc">XML-Dsig used to create the chain.</param>
        /// <returns>Chain of X509Certificates</returns>
        public async Task<List<X509Certificate2>> CertificateChain(string xmlDoc)
        {
            if (xmlDoc == null)
            {
                throw new ArgumentException("xmlDoc was null");
            }
            var xml = await _xmlUtil.LoadXml(xmlDoc);
            var xmlNamespaces = new XmlNamespaceManager(xml.NameTable);
            xmlNamespaces.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            var sigElement = (XmlElement)xml.SelectSingleNode("//ds:Signature[1]", xmlNamespaces);
            var signature = new SignedXml(xml);
            signature.LoadXml(sigElement);

            var certificates = new List<X509Certificate2>();
            foreach (var clause in signature.KeyInfo)
            {
                if (!(clause is KeyInfoX509Data)) continue;
                foreach (var x509Cert in ((KeyInfoX509Data)clause).Certificates)
                {
                    certificates.Add((X509Certificate2)x509Cert);
                }
            }

            return certificates;
        }
    }
}

