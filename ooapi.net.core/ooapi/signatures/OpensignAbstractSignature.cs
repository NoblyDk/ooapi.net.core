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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.XPath;
using org.openoces.ooapi.certificate;

namespace org.openoces.ooapi.signatures
{
    public abstract class OpensignAbstractSignature
    {
        private const String NamespaceuriOpenocesR1 = "http://www.openoces.org/2003/10/signature#";
        private const String NamespaceuriOpenocesR2 = "http://www.openoces.org/2006/07/signature#";

        protected XmlDocument Doc;
        private readonly IOcesCertificateFactory _ocesCertificateFactory;
        protected bool PopulatedInternalStructures;
        protected XmlElement Nscontext;
        private XmlElement SigElement;
        private SignedXml Signature;
        private readonly bool Valid = true;

        protected OpensignAbstractSignature(XmlDocument doc, IOcesCertificateFactory ocesCertificateFactory)
        {
            Doc = doc;
            _ocesCertificateFactory = ocesCertificateFactory;
            var xmlNamespaces = new XmlNamespaceManager(Doc.NameTable);
            xmlNamespaces.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            SigElement = (XmlElement)Doc.SelectSingleNode("//ds:Signature[1]", xmlNamespaces);
            Signature = new SignedXml(Doc);

            Valid = IsValidSignature().GetAwaiter().GetResult();
        }

        public Task<bool> IsValidSignature()
        {
            Signature.LoadXml(SigElement);
            return IsValidOces2Signature(Doc);
        }

        /// <summary>
        /// Valideringskode inspireret af:
        /// http://www.woloszyn.org/2008/01/03/how-to-verify-digital-signatures-of-xml-documents-without-wse3/
        /// </summary>
        public async Task<bool> IsValidOces2Signature(XmlDocument doc)
        {
            string signatureValue = await GetSignatureValue(doc);
            return await IsValidSignatureValue(signatureValue) && await AreValidReferences();
        }

        public Task<string> GetSignatureValue(XmlDocument doc)
        {
            XPathNavigator nav = doc.CreateNavigator();
            nav.MoveToFollowing("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
            return Task.FromResult(Regex.Replace(nav.InnerXml.Trim(), @"\s", ""));
        }

        public async Task<bool> IsValidSignatureValue(string signatureValue)
        {
            byte[] sigVal = Convert.FromBase64String(signatureValue);
            
            XmlNode signedInfo = Doc.GetElementsByTagName("ds:SignedInfo")[0];
            Hashtable ns = await RetrieveNameSpaces((XmlElement) signedInfo);
            await InsertNamespacesIntoElement(ns, (XmlElement) signedInfo);
            Stream signedInfoStream = await CanonicalizeNode(signedInfo);

            SHA256 sha256 = SHA256.Create();
            byte[] hashedSignedInfo = sha256.ComputeHash(signedInfoStream);

            string oid = CryptoConfig.MapNameToOID("SHA256");
            return Csp.VerifyHash(hashedSignedInfo, oid, sigVal);
        }

        public async Task<bool> AreValidReferences()
        {
            XmlNamespaceManager man = new XmlNamespaceManager(Doc.NameTable);
            man.AddNamespace("openoces", "http://www.openoces.org/2006/07/signature#");
            man.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            XmlNodeList messageReferences =
                Doc.SelectNodes("//openoces:signature/ds:Signature/ds:SignedInfo/ds:Reference", man);
            if (messageReferences == null || messageReferences.Count == 0)
            {
                return false;
            }

            bool result = true;
            foreach (XmlNode node in messageReferences)
            {
                result &= await IsValidReference(node);
            }
            return result;
        }

        public async Task<bool> IsValidReference(XmlNode node)
        {
            XPathNavigator elementNav = node.CreateNavigator();
            string elementID = elementNav.GetAttribute("URI", "");
            if (elementID.StartsWith("#"))
            {
                elementID = elementID.Substring(1);
            }

            XmlElement referencedNode = await RetrieveElementByAttribute(Doc, "Id", elementID);
            await InsertNamespacesIntoElement(await RetrieveNameSpaces((XmlElement)referencedNode.ParentNode), referencedNode);

            Stream canonicalizedNodeStream = await CanonicalizeNode(referencedNode);

            elementNav.MoveToFollowing("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
            HashAlgorithm hashAlg =
                (HashAlgorithm)CryptoConfig.CreateFromName(elementNav.GetAttribute("Algorithm", ""));
            byte[] hashedNode = hashAlg.ComputeHash(canonicalizedNodeStream);

            elementNav.MoveToFollowing("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
            byte[] digestValue = Convert.FromBase64String(elementNav.InnerXml);

            return hashedNode.SequenceEqual(digestValue);
        }

        RSACryptoServiceProvider Csp
        {
            get
            {
               return (RSACryptoServiceProvider)SigningCertificate.ExportCertificate().GetAwaiter().GetResult().PublicKey.Key;
            }
        }

        public OcesCertificate SigningCertificate
        {
            get
            {
                var certificates = new List<X509Certificate2>();
                foreach (var clause in Signature.KeyInfo)
                {
                    if (!(clause is KeyInfoX509Data)) continue;
                    foreach (var x509Cert in ((KeyInfoX509Data)clause).Certificates)
                    {
                        certificates.Add((X509Certificate2)x509Cert);
                    }
                }
                return _ocesCertificateFactory.Generate(certificates).GetAwaiter().GetResult();
            }
        }

        public Task<bool> Verify()
        {
            return Task.FromResult(Valid);
        }

        public Dictionary<String, SignatureProperty> SignatureProperties
        {
            get
            {
                var namespaceUri = Doc.DocumentElement.NamespaceURI;

                if (namespaceUri.Equals(NamespaceuriOpenocesR1))
                    return PropertiesR1;
                if (namespaceUri.Equals(NamespaceuriOpenocesR2))
                    return PropertiesR2;
                throw new ArgumentException("Unsupported namespace " + namespaceUri);
            }
        }

        public SignedDocument SignedDocument 
        {
            get
            {
                XmlNode signTextNode = RetrieveElementByAttribute(SigElement, "Id", "signText").GetAwaiter().GetResult();
                if (signTextNode == null)
                {
                    return new SignedDocument(UTF8Encoding.UTF8.GetBytes(this.SignatureProperties["signtext"].Value),"text/plain");
                }
                return new SignedDocument(Convert.FromBase64String(signTextNode.InnerText), signTextNode.Attributes["MimeType"].Value);
            }
        }

        public List<SignedDocument> SignedAttachments
        {
            get
            {
                List<SignedDocument> signedAttachments = new List<SignedDocument>();
                XmlNamespaceManager man = new XmlNamespaceManager(Doc.NameTable);
                man.AddNamespace("openoces", "http://www.openoces.org/2006/07/signature#");
                man.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
                XmlNodeList messageReferences = SigElement.SelectNodes("//openoces:signature/ds:Signature/ds:SignedInfo/ds:Reference", man);
                foreach (XmlNode node in messageReferences)
                {
                    String referenceID = node.Attributes["URI"].Value;
                    if (!"#ToBeSigned".Equals(referenceID))
                    {
                        if (referenceID.StartsWith("#"))
                        {
                            referenceID = referenceID.Substring(1);
                            XmlElement signedReference = RetrieveElementByAttribute(Doc, "Id", referenceID).GetAwaiter().GetResult();
                            byte[] signedContent = Convert.FromBase64String(signedReference.InnerText);
                            string mimeType = signedReference.Attributes["MimeType"].Value;
                            signedAttachments.Add(new SignedDocument(signedContent,mimeType));
                        }
                    }
                } 
                
                return signedAttachments;
            }
        }

        Dictionary<String, SignatureProperty> PropertiesR1
        {
            get
            {
                var signedContentLength = Signature.SignedInfo.References.Count;
                if (signedContentLength != 1)
                {
                    throw new InvalidProgramException("Expected signed content length 1, but found " + signedContentLength);
                }

                var xmlNamespaces = new XmlNamespaceManager(Doc.NameTable);
                xmlNamespaces.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

                var signaturProperties = Doc.SelectNodes("//ds:SignatureProperties/ds:SignatureProperty", xmlNamespaces);
                return ExtractPropertiesFromNodes(signaturProperties, "Name", "Value", xmlNamespaces).GetAwaiter().GetResult();
            }
        }

        Dictionary<String, SignatureProperty> PropertiesR2
        {
            get
            {
                foreach (Reference reference in Signature.SignedInfo.References)
                {
                    if ("#ToBeSigned".Equals(reference.Uri))
                    {
                        var xmlNamespaces = new XmlNamespaceManager(Doc.NameTable);
                        xmlNamespaces.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                        xmlNamespaces.AddNamespace("openoces", NamespaceuriOpenocesR2);
                        var signaturProperties = Doc.SelectNodes("//ds:SignatureProperty", xmlNamespaces);
                        return ExtractPropertiesFromNodes(signaturProperties, "openoces:Name", "openoces:Value", xmlNamespaces).GetAwaiter().GetResult();
                    }
                }
                return new Dictionary<String, SignatureProperty>();
            }
        }

        public Task<Dictionary<String, SignatureProperty>> ExtractPropertiesFromNodes(XmlNodeList nodes, string nameIdentifier, string valueIdentifier, XmlNamespaceManager xmlNamespaces)
        {
            var properties = new Dictionary<String, SignatureProperty>();

            foreach (XmlNode node in nodes)
            {
                XmlNode nameNode = node.SelectSingleNode(nameIdentifier, xmlNamespaces);
                XmlNode valueNode = node.SelectSingleNode(valueIdentifier, xmlNamespaces);

                var name = nameNode.FirstChild.Value;

                var value = valueNode.FirstChild.Value;
                var encodingAtrribute = valueNode.Attributes.GetNamedItem("Encoding");
                var encoding = encodingAtrribute != null ? encodingAtrribute.Value : null;

                //Never decode the rememberUseridToken clientside. It is encrypted and needs to stay b64 encoded.
                if (encoding != null && encoding.ToUpper().Equals("BASE64") && !name.Equals("rememberUseridToken"))
                {
                    value = Encoding.UTF8.GetString(Convert.FromBase64String(value));
                }

                var visibleToSigner = "yes".Equals(valueNode.Attributes.GetNamedItem("VisibleToSigner").Value);

                properties.Add(name, new SignatureProperty(name, value, visibleToSigner));
            }
            return Task.FromResult(properties);
        }


        public Task<Hashtable> RetrieveNameSpaces(XmlElement xEle)
        {
            Hashtable foundNamespaces = new Hashtable();
            XmlNode currentNode = xEle;

            while (currentNode != null)
            {
                if (currentNode.NodeType == XmlNodeType.Element && !string.IsNullOrEmpty(currentNode.Prefix))
                {
                    if (!foundNamespaces.ContainsKey("xmlns:" + currentNode.Prefix))
                    {
                        foundNamespaces.Add("xmlns:" + currentNode.Prefix, currentNode.NamespaceURI);
                    }
                }

                if (currentNode.Attributes != null && currentNode.Attributes.Count > 0)
                {
                    for (int i = 0; i < currentNode.Attributes.Count; i++)
                    {
                        if (currentNode.Attributes[i].Prefix.Equals("xmlns") || currentNode.Attributes[i].Name.Equals("xmlns"))
                        {
                            if (!foundNamespaces.ContainsKey(currentNode.Attributes[i].Name))
                            {
                                foundNamespaces.Add(currentNode.Attributes[i].Name, currentNode.Attributes[i].Value);
                            }
                        }
                    }
                }
                currentNode = currentNode.ParentNode;
            }
            return Task.FromResult(foundNamespaces);
        }

        public Task InsertNamespacesIntoElement(Hashtable namespacesHash, XmlElement node)
        {
            XPathNavigator nav = node.CreateNavigator();
            if (string.IsNullOrEmpty(nav.Prefix) && string.IsNullOrEmpty(nav.GetAttribute("xmlns", "")))
            {
                nav.CreateAttribute("", "xmlns", "", nav.NamespaceURI);
            }
            foreach (DictionaryEntry namespacePair in namespacesHash)
            {
                string[] attrName = ((string)namespacePair.Key).Split(':');
                if (attrName.Length > 1 && !node.HasAttribute(attrName[0] + ":" + attrName[1]))
                {
                    nav.CreateAttribute(attrName[0], attrName[1], "", (string)namespacePair.Value);
                }
            }
            return Task.CompletedTask;
        }

        public Task<Stream> CanonicalizeNode(XmlNode node)
        {
            XmlNodeReader reader = new XmlNodeReader(node);
            Stream stream = new MemoryStream();
            XmlWriter writer = new XmlTextWriter(stream, Encoding.UTF8);

            writer.WriteNode(reader, false);
            writer.Flush();

            stream.Position = 0;
            XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
            transform.LoadInput(stream);
            return Task.FromResult((Stream)transform.GetOutput());
        }

        public async Task<XmlElement> RetrieveElementByAttribute(XmlNode xDoc, string attributeName, string attributeValue)
        {
            XmlElement foundElement = null;
            foreach (XmlNode node in xDoc)
            {
                if (node.HasChildNodes)
                {
                    foundElement = await RetrieveElementByAttribute(node, attributeName, attributeValue);
                }
                if (foundElement == null && node.Attributes != null && node.Attributes[attributeName] != null && node.Attributes[attributeName].Value.ToLower().Equals(attributeValue.ToLower()))
                {
                    foundElement = (XmlElement)node;
                    break;
                }
                if (foundElement != null)
                {
                    break;
                }
            }
            return foundElement;
        }
    }
}
