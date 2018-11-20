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
using System.Text;
using System.Threading.Tasks;
using org.openoces.ooapi.certificate;

namespace org.openoces.ooapi.environment
{
    public class RootCertificates : IRootCertificates
    {
        public Task<Dictionary<OcesEnvironment, X509Certificate2>> TheRootCertificates =>
            LoadRootCertificates();

        const string ProductionCertificateOcesII =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIGHDCCBASgAwIBAgIES45gAzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJE\n" +
            "SzESMBAGA1UEChMJVFJVU1QyNDA4MSIwIAYDVQQDExlUUlVTVDI0MDggT0NFUyBQ\n" +
            "cmltYXJ5IENBMB4XDTEwMDMwMzEyNDEzNFoXDTM3MTIwMzEzMTEzNFowRTELMAkG\n" +
            "A1UEBhMCREsxEjAQBgNVBAoTCVRSVVNUMjQwODEiMCAGA1UEAxMZVFJVU1QyNDA4\n" +
            "IE9DRVMgUHJpbWFyeSBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\n" +
            "AJlJodr3U1Fa+v8HnyACHV81/wLevLS0KUk58VIABl6Wfs3LLNoj5soVAZv4LBi5\n" +
            "gs7E8CZ9w0F2CopW8vzM8i5HLKE4eedPdnaFqHiBZ0q5aaaQArW+qKJx1rT/AaXt\n" +
            "alMB63/yvJcYlXS2lpexk5H/zDBUXeEQyvfmK+slAySWT6wKxIPDwVapauFY9QaG\n" +
            "+VBhCa5jBstWS7A5gQfEvYqn6csZ3jW472kW6OFNz6ftBcTwufomGJBMkonf4ZLr\n" +
            "6t0AdRi9jflBPz3MNNRGxyjIuAmFqGocYFA/OODBRjvSHB2DygqQ8k+9tlpvzMRr\n" +
            "kU7jq3RKL+83G1dJ3/LTjCLz4ryEMIC/OJ/gNZfE0qXddpPtzflIPtUFVffXdbFV\n" +
            "1t6XZFhJ+wBHQCpJobq/BjqLWUA86upsDbfwnePtmIPRCemeXkY0qabC+2Qmd2Fe\n" +
            "xyZphwTyMnbqy6FG1tB65dYf3mOqStmLa3RcHn9+2dwNfUkh0tjO2FXD7drWcU0O\n" +
            "I9DW8oAypiPhm/QCjMU6j6t+0pzqJ/S0tdAo+BeiXK5hwk6aR+sRb608QfBbRAs3\n" +
            "U/q8jSPByenggac2BtTN6cl+AA1Mfcgl8iXWNFVGegzd/VS9vINClJCe3FNVoUnR\n" +
            "YCKkj+x0fqxvBLopOkJkmuZw/yhgMxljUi2qYYGn90OzAgMBAAGjggESMIIBDjAP\n" +
            "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjARBgNVHSAECjAIMAYGBFUd\n" +
            "IAAwgZcGA1UdHwSBjzCBjDAsoCqgKIYmaHR0cDovL2NybC5vY2VzLnRydXN0MjQw\n" +
            "OC5jb20vb2Nlcy5jcmwwXKBaoFikVjBUMQswCQYDVQQGEwJESzESMBAGA1UEChMJ\n" +
            "VFJVU1QyNDA4MSIwIAYDVQQDExlUUlVTVDI0MDggT0NFUyBQcmltYXJ5IENBMQ0w\n" +
            "CwYDVQQDEwRDUkwxMB8GA1UdIwQYMBaAFPZt+LFIs0FDAduGROUYBbdezAY3MB0G\n" +
            "A1UdDgQWBBT2bfixSLNBQwHbhkTlGAW3XswGNzANBgkqhkiG9w0BAQsFAAOCAgEA\n" +
            "VPAQGrT7dIjD3/sIbQW86f9CBPu0c7JKN6oUoRUtKqgJ2KCdcB5ANhCoyznHpu3m\n" +
            "/dUfVUI5hc31CaPgZyY37hch1q4/c9INcELGZVE/FWfehkH+acpdNr7j8UoRZlkN\n" +
            "15b/0UUBfGeiiJG/ugo4llfoPrp8bUmXEGggK3wyqIPcJatPtHwlb6ympfC2b/Ld\n" +
            "v/0IdIOzIOm+A89Q0utx+1cOBq72OHy8gpGb6MfncVFMoL2fjP652Ypgtr8qN9Ka\n" +
            "/XOazktiIf+2Pzp7hLi92hRc9QMYexrV/nnFSQoWdU8TqULFUoZ3zTEC3F/g2yj+\n" +
            "FhbrgXHGo5/A4O74X+lpbY2XV47aSuw+DzcPt/EhMj2of7SA55WSgbjPMbmNX0rb\n" +
            "oenSIte2HRFW5Tr2W+qqkc/StixgkKdyzGLoFx/xeTWdJkZKwyjqge2wJqws2upY\n" +
            "EiThhC497+/mTiSuXd69eVUwKyqYp9SD2rTtNmF6TCghRM/dNsJOl+osxDVGcwvt\n" +
            "WIVFF/Onlu5fu1NHXdqNEfzldKDUvCfii3L2iATTZyHwU9CALE+2eIA+PIaLgnM1\n" +
            "1oCfUnYBkQurTrihvzz9PryCVkLxiqRmBVvUz+D4N5G/wvvKDS6t6cPCS+hqM482\n" +
            "cbBsn0R9fFLO4El62S9eH1tqOzO20OAOK65yJIsOpSE=\n" +
            "-----END CERTIFICATE-----"; 
         
        const string PreproductionCertificateOcesII =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIGSDCCBDCgAwIBAgIES+pulDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJE\n" +
            "SzESMBAGA1UEChMJVFJVU1QyNDA4MSwwKgYDVQQDEyNUUlVTVDI0MDggU3lzdGVt\n" +
            "dGVzdCBWSUkgUHJpbWFyeSBDQTAeFw0xMDA1MTIwODMyMTRaFw0zNzAxMTIwOTAy\n" +
            "MTRaME8xCzAJBgNVBAYTAkRLMRIwEAYDVQQKEwlUUlVTVDI0MDgxLDAqBgNVBAMT\n" +
            "I1RSVVNUMjQwOCBTeXN0ZW10ZXN0IFZJSSBQcmltYXJ5IENBMIICIjANBgkqhkiG\n" +
            "9w0BAQEFAAOCAg8AMIICCgKCAgEApuuMpdHu/lXhQ+9TyecthOxrg5hPgxlK1rpj\n" +
            "syBNDEmOEpmOlK8ghyZ7MnSF3ffsiY+0jA51p+AQfYYuarGgUQVO+VM6E3VUdDpg\n" +
            "WEksetCYY8L7UrpyDeYx9oywT7E+YXH0vCoug5F9vBPnky7PlfVNaXPfgjh1+66m\n" +
            "lUD9sV3fiTjDL12GkwOLt35S5BkcqAEYc37HT69N88QugxtaRl8eFBRumj1Mw0LB\n" +
            "xCwl21GdVY4EjqH1Us7YtRMRJ2nEFTCRWHzm2ryf7BGd80YmtJeL6RoiidwlIgzv\n" +
            "hoFhv4XdLHwzaQbdb9s141q2s9KDPZCGcgIgeXZdqY1Vz7UBCMiBDG7q2S2ni7wp\n" +
            "UMBye+iYVkvJD32srGCzpWqG7203cLyZCjq2oWuLkL807/Sk4sYleMA4YFqsazIf\n" +
            "V+M0OVrJCCCkPysS10n/+ioleM0hnoxQiupujIGPcJMA8anqWueGIaKNZFA/m1IK\n" +
            "wnn0CTkEm2aGTTEwpzb0+dCATlLyv6Ss3w+D7pqWCXsAVAZmD4pncX+/ASRZQd3o\n" +
            "SvNQxUQr8EoxEULxSae0CPRyGwQwswGpqmGm8kNPHjIC5ks2mzHZAMyTz3zoU3h/\n" +
            "QW2T2U2+pZjUeMjYhyrReWRbOIBCizoOaoaNcSnPGUEohGUyLPTbZLpWsm3vjbyk\n" +
            "7yvPqoUCAwEAAaOCASowggEmMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD\n" +
            "AgEGMBEGA1UdIAQKMAgwBgYEVR0gADCBrwYDVR0fBIGnMIGkMDqgOKA2hjRodHRw\n" +
            "Oi8vY3JsLnN5c3RlbXRlc3Q3LnRydXN0MjQwOC5jb20vc3lzdGVtdGVzdDcuY3Js\n" +
            "MGagZKBipGAwXjELMAkGA1UEBhMCREsxEjAQBgNVBAoTCVRSVVNUMjQwODEsMCoG\n" +
            "A1UEAxMjVFJVU1QyNDA4IFN5c3RlbXRlc3QgVklJIFByaW1hcnkgQ0ExDTALBgNV\n" +
            "BAMTBENSTDEwHwYDVR0jBBgwFoAUI7pMMZDh08zTG7MbWrbIRc3Tg5cwHQYDVR0O\n" +
            "BBYEFCO6TDGQ4dPM0xuzG1q2yEXN04OXMA0GCSqGSIb3DQEBCwUAA4ICAQCRJ9TM\n" +
            "7sISJBHQwN8xdey4rxA0qT7NZdKICcIxyIC82HIOGAouKb3oHjIoMgxIUhA3xbU3\n" +
            "Putr4+Smnc1Ldrw8AofLGlFYG2ypg3cpF9pdHrVdh8QiERozLwfNPDgVeCAnjKPN\n" +
            "t8mu0FWBS32tiVM5DEOUwDpoDDRF27Ku9qTFH4IYg90wLHfLi+nqc2HwVBUgDt3t\n" +
            "XU6zK4pzM0CpbrbOXPJOYHMvaw/4Em2r0PZD+QOagcecxPMWI65t2h/USbyO/ah3\n" +
            "VKnBWDkPsMKjj5jEbBVRnGZdv5rcJb0cHqQ802eztziA4HTbSzBE4oRaVCrhXg/g\n" +
            "6Jj8/tZlgxRI0JGgAX2dvWQyP4xhbxLNCVXPdvRV0g0ehKvhom1FGjIz975/DMav\n" +
            "kybh0gzygq4sY9Fykl4oT4rDkDvZLYIxS4u1BrUJJJaDzHCeXmZqOhx8She+Fj9Y\n" +
            "wVVRGfxT4FL0Qd3WAtaCVyhSQ6SkZgrPvzAmxOUruI6XhEhYGlP5O8WFETiATxuZ\n" +
            "AJNuKMJtibfRhMNsQ+TVv/ZPr5Swe+3DIQtmt1MIlGlTn4k40z4s6gDGKiFwAYXj\n" +
            "d/kID32R/hJPE41o9+3nd8aHZhBy2lF0jKAmr5a6Lbhg2O7zjGq7mQ3MceNeebuW\n" +
            "XD44AxIinryzhqnEWI+BxdlFaia3U7o2+HYdHw==\n" +
            "-----END CERTIFICATE-----";

        private async Task<Dictionary<OcesEnvironment, X509Certificate2>> LoadRootCertificates()
        {
            var certificates = new Dictionary<OcesEnvironment, String>
                     {
                       {OcesEnvironment.OcesII_DanidEnvPreprod, PreproductionCertificateOcesII},
                       {OcesEnvironment.OcesII_DanidEnvProd, ProductionCertificateOcesII}
                     };

            var result = new Dictionary<OcesEnvironment, X509Certificate2>();
            foreach (var environment in certificates.Keys)
            {
                result.Add(environment, await GenerateCertificate(certificates[environment]));
            }
            return result;
        }

        private Task<X509Certificate2> GenerateCertificate(string certificate)
        {
            var encoding = new ASCIIEncoding();
            return Task.FromResult(new X509Certificate2(encoding.GetBytes(certificate)));
        }

        /// <summary>
        /// Gets root certificate of the given <code>Environment</code>
        /// </summary>
        public async Task<X509Certificate2> LookupCertificate(OcesEnvironment environment)
        {
            var tr = await TheRootCertificates;
            if (!(tr).ContainsKey(environment))
            {
                throw new ArgumentException("No certificate for: " + environment);
            }
            return tr[environment];
        }

        public async Task<X509Certificate2> LookupCertificateBySubjectDn(X500DistinguishedName subjectDn)
        {
            foreach (var entry in await TheRootCertificates)
            {
                if (entry.Value.SubjectName.Decode(X500DistinguishedNameFlags.None)?.ToLower() == subjectDn.Decode(X500DistinguishedNameFlags.None)?.ToLower())
                {
                    return entry.Value;
                }
            }
            throw new ArgumentException("No certificate for subjectDn: " + subjectDn.Format(false));
        }

        public async Task<bool> HasCertificate(OcesEnvironment environment)
        {
            return (await TheRootCertificates).ContainsKey(environment);
        }

        /// <summary>
        /// Gets <code>Environment</code> for given <code>CA</code>
        /// </summary>
        public async Task<OcesEnvironment> GetEnvironment(Ca ca)
        {
            if (ca == null)
            {
                throw new ArgumentException("Ca is null");
            }
            if (!ca.IsRoot)
            {
                return await GetEnvironment(ca.IssuingCa);
            }
            foreach (var e in await TheRootCertificates)
            {
                if (e.Value.Equals(ca.Certificate))
                {
                    return e.Key;
                }
            }
            throw new ArgumentException(ca + " is not a known root certificate");
        }
    }
}
