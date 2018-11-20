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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace org.openoces.ooapi.validation
{
    public class CrlDistributionPointsExtractor : ICrlDistributionPointsExtractor
    {
        private const int UniformResourceIdentifier = 6;
        private const int DirectoryName = 4;

        public async Task<CrlDistributionPoints> ExtractCrlDistributionPointsAsync(X509Certificate2 certificate)
        {
            var distributionPointsExtension = await ExtractCrlDistributionPointsExtensionAsync(certificate);

            var fullCrlDistributionPoint = await ExtractFullCrlDistributionPointAsync(distributionPointsExtension);
            var partitionedCrlDistributionPoint = await ExtractPartitionedCrlDistributionPointAsync(distributionPointsExtension);

            return new CrlDistributionPoints(fullCrlDistributionPoint, partitionedCrlDistributionPoint);
        }

        private Task<CrlDistPoint> ExtractCrlDistributionPointsExtensionAsync(X509Certificate2 certificate)
        {
            var bouncyCastleCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
            var extension = bouncyCastleCertificate.GetExtensionValue(new DerObjectIdentifier(ObjectIdentifiers.CrlDistributionPointsExtension));
            var stream = new Asn1InputStream(extension.GetOctetStream());

            return Task.FromResult(CrlDistPoint.GetInstance(stream.ReadObject()));
        }

        private async Task<string> ExtractFullCrlDistributionPointAsync(CrlDistPoint distributionPointsExtension)
        {
            var crlDistributionPointGeneralName = await ExtractGeneralNameAsync(distributionPointsExtension, UniformResourceIdentifier);
            return crlDistributionPointGeneralName?.ToString();
        }

        private async Task<string> ExtractPartitionedCrlDistributionPointAsync(CrlDistPoint distributionPointsExtension)
        {
            var directoryNames = await ExtractGeneralNameAsync(distributionPointsExtension, DirectoryName);
            return await ExtractPartitionedCrlDistributionPointAsync(directoryNames);
        }

        private async Task<string> ExtractPartitionedCrlDistributionPointAsync(IAsn1Convertible directoryName)
        {
            var ds = (DerSequence) directoryName.ToAsn1Object();

            var partitionedCrlDistributionPoint = "";
            foreach (Asn1Set dset in ds)
            {
                partitionedCrlDistributionPoint = await BuildPartitionedCrlDistributionPointAsync(partitionedCrlDistributionPoint, dset);
            }
            return partitionedCrlDistributionPoint;
        }

        private Task<string> BuildPartitionedCrlDistributionPointAsync(string partitionedCrlDistributionPoint, Asn1Set dset)
        {
            foreach (DerSequence relativeDn in dset)
            {
                var relativeDnOid = ((DerObjectIdentifier)relativeDn[0]).Id;
                var relativeDnName = (string)X509Name.RFC2253Symbols[new DerObjectIdentifier(relativeDnOid)];
                var relativeDnValue = ((DerStringBase)relativeDn[1]).GetString();

                var comma = partitionedCrlDistributionPoint.Length > 0 ? "," : "";
                partitionedCrlDistributionPoint = relativeDnName + "=" + relativeDnValue + comma + partitionedCrlDistributionPoint;
            }
            return Task.FromResult(partitionedCrlDistributionPoint);
        }

        private Task<Asn1Encodable> ExtractGeneralNameAsync(CrlDistPoint distributionPointsExtension, int tagNumber)
        {
            foreach (var distributionPoint in distributionPointsExtension.GetDistributionPoints())
            {
                DistributionPointName dpn = distributionPoint.DistributionPointName;
                if (dpn.PointType == DistributionPointName.FullName)
                {
                    foreach (var generalName in GeneralNames.GetInstance(dpn.Name).GetNames())
                    {
                        if (generalName.TagNo == tagNumber)
                        {
                            return Task.FromResult(generalName.Name);
                        }
                    }
                }
            }
            return Task.FromResult<Asn1Encodable>(null);
        }
    }
}
