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
using System.Xml;
using org.openoces.ooapi.certificate;

namespace org.openoces.ooapi.signatures
{
    public class OpensignSignature : OpensignAbstractSignature
    {
        public OpensignSignature(XmlDocument doc, IOcesCertificateFactory ocesCertificateFactory)
            : base(doc, ocesCertificateFactory)
        {
        }

        public string Signtext
        {
            get { return SignatureProperties["signtext"].Value; }
        }

        public string StylesheetDigest
        {
            get {
                XmlNamespaceManager man = new XmlNamespaceManager(Doc.NameTable);
                man.AddNamespace("openoces", "http://www.openoces.org/2006/07/signature#");
                man.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

                var nodes = Doc.SelectNodes("//ds:SignatureProperty[@Target=\"signature\"]", man);
                if (nodes == null)
                {
                    return null;
                }

                for (int i = 0; i < nodes.Count; i++)
                {
                    var node = nodes[i];
                    var children = node.ChildNodes;
                    var nameElm = children[0];
                    var signatureProperty = nameElm.FirstChild.Value;
                    if (signatureProperty != null && signatureProperty.ToUpper().Equals("STYLESHEETDIGEST"))
                    {
                        return children[1].FirstChild.Value;
                    }
                }

                return null;
            }
        }

    }
}
