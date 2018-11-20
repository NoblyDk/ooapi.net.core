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
using org.openoces.ooapi.exceptions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace org.openoces.ooapi.utils
{
    public class X509CertificatePropertyExtrator : IX509CertificatePropertyExtrator
    {
        public Task<string> GetEmailAddress(X509Certificate2 certificate)
        {
            var sanExtension = certificate.Extensions[ObjectIdentifiers.SubjectAlternativeName];
            if (sanExtension != null)
            {
                var email = sanExtension.Format(false);
                return Task.FromResult(email.Substring(email.LastIndexOf("=") + 1));
            }
            return Task.FromResult<string>(null);
        }

        public Task<X509KeyUsageExtension> GetKeyUsage(X509Certificate2 certificate)
        {
            var keyExtension = certificate.Extensions[ObjectIdentifiers.KeyUsage];
            if (keyExtension != null)
            {
                return Task.FromResult((X509KeyUsageExtension)keyExtension);
            }
            return Task.FromResult<X509KeyUsageExtension>(null);
        }

        public Task<string> GetSubjectOrganizationalUnit(X509Certificate2 certificate)
        {
            var x509Name = new X509Name(certificate.SubjectName.Name);
            var oids = x509Name.GetOidList();

            for (int i = 0; i < oids.Count; i++)
            {
                var oid = oids[i];
                if (ObjectIdentifiers.OrganizationalUnit.Equals(oid.ToString()))
                {
                    return Task.FromResult(x509Name.GetValueList()[i].ToString());
                }
            }
            return Task.FromResult<string>(null);
        }

        public Task<string> GetSubjectCommonName(X509Certificate2 certificate)
        {
            var asnEncodedData = new AsnEncodedData(new Oid(ObjectIdentifiers.CommonName), certificate.SubjectName.RawData);
            return Task.FromResult(asnEncodedData.Format(false));
        }

        public async Task<bool> HasPseudonym(X509Certificate2 certificate)
        {
            return "Pseudonym" == await GetSubjectCommonName(certificate);
        }

        public Task<string> GetElementInX509Name(X509Certificate2 certificate, string element)
        {
            var asnEncodedData = new AsnEncodedData(new Oid(element), certificate.SubjectName.RawData);
            return Task.FromResult(asnEncodedData.Format(false));
        }

        public Task<X509BasicConstraintsExtension> GetBasicConstraints(X509Certificate2 certificate)
        {
            return Task.FromResult((X509BasicConstraintsExtension)certificate.Extensions[ObjectIdentifiers.BasicConstraints]);
        }

        public async Task<string> GetCertificatePolicyOid(X509Certificate2 certificate)
        {
            var extensions = await GetX509Extensions(certificate);
            var e = extensions.GetExtension(X509Extensions.CertificatePolicies);
            var extIn = new Asn1InputStream(e.Value.GetOctetStream());
            var piSeq = (DerSequence)extIn.ReadObject();
            if (piSeq.Count != 1)
            {
                throw new NonOcesCertificateException("Could not find Certificate PolicyOID");
            }
            var pi = PolicyInformation.GetInstance(piSeq[0]);
            return pi.PolicyIdentifier.Id;
        }

        public async Task<string> GetOcspUrl(X509Certificate2 certificate)
        {
            var extensions = await GetX509Extensions(certificate);
            var authorityInfoAccess = extensions.GetExtension(X509Extensions.AuthorityInfoAccess);
            var instance = AuthorityInformationAccess.GetInstance(authorityInfoAccess);
            AccessDescription[] authorityInformationAccess = instance.GetAccessDescriptions();
            if (authorityInformationAccess == null)
            {
                throw new InvalidOperationException("Could not find ocsp url for certificate " + certificate);
            }

            var ocspUrl = await GetAccessDescriptionUrlForOid(AccessDescription.IdADOcsp, authorityInformationAccess);

            if (ocspUrl == null)
            {
                throw new InvalidOperationException("Could not find ocsp url for certificate " + certificate);
            }
            return ocspUrl;
        }

        public async Task<string> GetCaIssuerUrl(X509Certificate2 certificate)
        {
            var extensions = await GetX509Extensions(certificate);
            AccessDescription[] authorityInformationAccess = AuthorityInformationAccess.GetInstance(extensions.GetExtension(X509Extensions.AuthorityInfoAccess)).GetAccessDescriptions();
            if (authorityInformationAccess == null)
            {
                throw new InvalidCaIssuerUrlException("Could not find CA issuer for certificate " + certificate);
            }

            var caIssuerUrl = await GetAccessDescriptionUrlForOid(AccessDescription.IdADCAIssuers, authorityInformationAccess);

            if (caIssuerUrl == null)
            {
                throw new InvalidCaIssuerUrlException("Could not find CA issuer for certificate " + certificate);
            }
            return caIssuerUrl;
        }

        private Task<string> GetAccessDescriptionUrlForOid(DerObjectIdentifier oid, AccessDescription[] authorityInformationAccessArray)
        {
            foreach (AccessDescription authorityInformationAcces in authorityInformationAccessArray)
            {
                if (oid.Equals(authorityInformationAcces.AccessMethod))
                {
                    var name = authorityInformationAcces.AccessLocation;
                    return Task.FromResult(((DerIA5String)name.Name).GetString());
                }
            }
            return null;
        }

        private Task<X509Extensions> GetX509Extensions(X509Certificate2 certificate)
        {
            try
            {
                var inputStream = new Asn1InputStream(certificate.RawData);
                var certificateAsAsn1 = inputStream.ReadObject();
                var certificateStructure = X509CertificateStructure.GetInstance(certificateAsAsn1);
                var toBeSignedPart = certificateStructure.TbsCertificate;
                var extensions = toBeSignedPart.Extensions;
                if (extensions == null)
                {
                    throw new NonOcesCertificateException("No X509 extensions found");
                }
                return Task.FromResult(extensions);
            }
            catch (CertificateEncodingException e)
            {
                throw new ArgumentException("Error while extracting Access Description", e);
            }
        }
    }
}
