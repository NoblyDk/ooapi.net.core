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
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.certificate;
using X509Certificate=Org.BouncyCastle.X509.X509Certificate;

namespace org.openoces.ooapi.utils.ocsp
{
    public class RequestGenerator : IRequestGenerator
    {
        public Task<OcspReqAndId> CreateOcspRequest(IOcesCertificate certificate)
        {
            return CreateOcspRequest(certificate.IssuingCa.Certificate, SerialNumberConverter.FromCertificate(certificate));
        }

        public Task<OcspReqAndId> CreateOcspRequest(X509Certificate2 rootCertificate, string serialNumber)
        {
            var bouncyCastleCertificate = new X509CertificateParser().ReadCertificate(rootCertificate.RawData);

            return CreateOcspRequest(bouncyCastleCertificate, serialNumber);
        }

        public async Task<OcspReqAndId> CreateOcspRequest(X509Certificate rootCertificate, string serialNumber)
        {
            Asn1OctetString issuerNameHash = await CreateIssuerNameHash(rootCertificate);
            Asn1OctetString issuerKeyHash = await CreateIssuerKeyHash(rootCertificate);

            return await CreateOcspRequest(issuerNameHash, issuerKeyHash, serialNumber);
        }

        private Task<OcspReqAndId> CreateOcspRequest(Asn1OctetString issuerNameHash, Asn1OctetString issuerKeyHash, string serialNumber)
        {
            var hashAlgorithm = new AlgorithmIdentifier(X509ObjectIdentifiers.IdSha1, DerNull.Instance);
            var derSerialNumber = new DerInteger(new BigInteger(serialNumber));
            var id = new CertID(hashAlgorithm, issuerNameHash, issuerKeyHash, derSerialNumber);

            var generator = new OcspReqGenerator();
            generator.AddRequest(new CertificateID(id));
            return Task.FromResult(new OcspReqAndId(generator.Generate(), id));
        }

        private Task<Asn1OctetString> CreateIssuerNameHash(X509Certificate rootCertificate)
        {
            return CreateDigestFromBytes(rootCertificate.SubjectDN.GetEncoded());
        }

        private Task<Asn1OctetString> CreateIssuerKeyHash(X509Certificate rootCertificate)
        {
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rootCertificate.GetPublicKey());
            byte[] bytes = publicKeyInfo.PublicKeyData.GetBytes();
            return CreateDigestFromBytes(bytes);
        }

        private Task<Asn1OctetString> CreateDigestFromBytes(byte[] bytes)
        {
            var digest = new Sha1Digest();

            digest.BlockUpdate(bytes, 0, bytes.Length);
            var digestBytes = new byte[digest.GetDigestSize()];
            digest.DoFinal(digestBytes, 0);
            return Task.FromResult<Asn1OctetString>(new DerOctetString(digestBytes));
        }
    }
}
