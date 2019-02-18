using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ooapi.net.core.ooapi.pidservice;
using org.openoces.ooapi;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.ldap;
using org.openoces.ooapi.pidservice;
using org.openoces.ooapi.ping;
using org.openoces.ooapi.ridservice;
using org.openoces.ooapi.signatures;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.utils.ocsp;
using org.openoces.ooapi.validation;
using org.openoces.securitypackage;
using org.openoces.serviceprovider;

namespace EnvironmentTester
{
    /// <summary>
    /// Use the Main method of this Class to test if the Environment has been setup correctly. 
    /// </summary>
    public class EnvironmentTester
    {
        //private static readonly IConfigurationChecker _configurationChecker;
        //private static readonly ICrlDistributionPointsExtractor _crlDistributionPointsExtractor;
        //private static readonly ICaCrlRevokedChecker _caCrlRevokedChecker;
        //private static readonly IEnvironments _environments;
        //private static readonly IX509CertificatePropertyExtrator _x509CertificatePropertyExtrator;
            

        static readonly Dictionary<string, OcesEnvironment> EnvDictionary = CreateEnvDictionaryAsync();

        private static IConfigurationRoot Configuration;
        private static IServiceProvider ServiceProvider;
        private static string _logOnto = "Nobly";
        private static string _wsUrl = "https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidws/";
        private static string _pfxFile = @"C:\certs\hrportal-vault-nemid-test-certificate-20190214.pfx";
        private static string _pfxPassword = "";

        private static string loginData = @"<?xml version=""1.0"" encoding=""UTF-8"" ?>
<openoces:signature xmlns:openoces=""http://www.openoces.org/2006/07/signature#"" version=""0.1""><ds:Signature xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"" Id=""signature"">
<ds:SignedInfo xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"" xmlns:openoces=""http://www.openoces.org/2006/07/signature#"">
<ds:CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315""></ds:CanonicalizationMethod>
<ds:SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256""></ds:SignatureMethod>
<ds:Reference URI=""#ToBeSigned"">
<ds:DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256""></ds:DigestMethod>
<ds:DigestValue>yRFG8Fzff3LS8/zbR5lGT2/F6WEzFnCW14M29BVOUSs=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
fGMuWCOY6ftxLLHLoy05ARGlJC7jpeOjcIlOg3+6XiTMO96xrp4yvrQi7zzBnXPJYU/75Q97VQPN
YKWV2nfsqeyAcPAYhuT48KJEoDraC/BnaNJMCu/4/LQkX9yjKkHShm8vEvdfHOEwNpiFWqn8pKpI
lC+jnWFJNcJ0aVRxrFP/+ThYpjVuPDgxzahvYpjOpUhRtXOpMF+l7JHyH1/h+Yb5iJSO1EsYai/j
1woagSi46Ywxg+HjnN3Sz0S6kRFUmpl/hqTs3waUonaYUg94vWXj6HNgmtzMsVq7SwwscVNUj13h
+DqgT3l1CUO0PKVgEjb3jty1/UqPRTKYsu6MDg==
</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>
MIIFQTCCAymgAwIBAgIEWBh+dDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJESzESMBAGA1UE
ChMJVFJVU1QyNDA4MSwwKgYDVQQDEyNUUlVTVDI0MDggU3lzdGVtdGVzdCBWSUkgUHJpbWFyeSBD
QTAeFw0xNzA3MDQwNjE4NDNaFw0zMjA3MDQwNjQ4NDNaMEgxCzAJBgNVBAYTAkRLMRIwEAYDVQQK
DAlUUlVTVDI0MDgxJTAjBgNVBAMMHFRSVVNUMjQwOCBTeXN0ZW10ZXN0IFhYSUkgQ0EwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbBwqNV+FheMxPeQSYkL8ix0EAN3Au+227n2GSKakg
QhF7yNVy6MTpYlqQ7AQtc8tqK/Zj1haN5Awq4RupTzpgu7Ehn6BspD1TV3CcGJ4NzSXrm9p/fR75
lbHCfMJYwG7wY5sgL+mYXLC+oEY3HfsqLI8Fi8feksnROWSAjBw0pdnIh59NIaSUOY4ED9jVfih7
Mg95LPib7cLYofA1sZwWJeXXrXfJi+m9uIUyOdbsoTHyZS2tg7srzYJ4oRaQKM2LuJ4B5BaddKoI
ucDXMGiz+3r65jSC6YPUp8qJO8Bo0KLqevteNOWwTIyKr6NbOTkopFzIWBpziw9Q+MMTCb63AgMB
AAGjggEqMIIBJjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjARBgNVHSAECjAIMAYG
BFUdIAAwga8GA1UdHwSBpzCBpDA6oDigNoY0aHR0cDovL2NybC5zeXN0ZW10ZXN0Ny50cnVzdDI0
MDguY29tL3N5c3RlbXRlc3Q3LmNybDBmoGSgYqRgMF4xCzAJBgNVBAYTAkRLMRIwEAYDVQQKEwlU
UlVTVDI0MDgxLDAqBgNVBAMTI1RSVVNUMjQwOCBTeXN0ZW10ZXN0IFZJSSBQcmltYXJ5IENBMQ0w
CwYDVQQDEwRDUkwxMB8GA1UdIwQYMBaAFCO6TDGQ4dPM0xuzG1q2yEXN04OXMB0GA1UdDgQWBBSr
qAFEGbCzQ5na+nzM0gAYA+c8vzANBgkqhkiG9w0BAQsFAAOCAgEAnOAB59t3EGqIUC/4I1DpIltO
2Il7ldWQ0bEN/eVjHoz4Uyd1T2wIRYS+jGUBMMKAJtHfMUzuqgEee871eVuy4wi6dlUGMeTQwMSe
3tToZFIA6lS3CSW2wklJQN7GepwkLc2JXKRiXNpbKmdoODIYtXZI4TirtJdQ855wqqlEBHxCoXrJ
p6O6EGkGQw6kDSiP/gmx2MC6v/4ew25Goq6y6Vpbo6N4j3HOv/TZKqvAz398hTR1TBNz1wHa0Y5Z
UnJrV+sBjABvTjt0cyy/ml/5wF10INavf8wWv4xvV/D3X/4WysVQNTsInCPoBmYFNdxjqpNwNDwf
3as9JZtSUBNeTsC2CN3zfovfqxC/MPqvMwBo+ovL2PjhMmyIc2UOPxBpf3sf90U48D4EnQyz+gNZ
EjifCmKLW+Y2S8Jt7Bl1UCnEU8i4q3XFJjIJlj70FCAcolVymMEqxZblU4v1ricrtZloPNzUU2rV
1WKPyWypLqd5NpbkdgMsXHLC+XV8jfpk+m2/Yf4g4lbB5L3corbswLUvjWQvhtFVznKQNbiKj8ud
uCPS2S5MnP6lZOXN8jcv6u337sHRZNbeYYaHcmsin2vARS5AeeT9CW+bqFZ4ofDOwsr9fQ2jN+vd
IX2ZPUlK5KBZ9Lo2CikaEQsxXLOv6PfBZqo6ukkOeqTqnVYCW68=
</ds:X509Certificate>
</ds:X509Data>
<ds:X509Data>
<ds:X509Certificate>
MIIGDTCCBPWgAwIBAgIEW6sEqDANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJESzESMBAGA1UE
CgwJVFJVU1QyNDA4MSUwIwYDVQQDDBxUUlVTVDI0MDggU3lzdGVtdGVzdCBYWElJIENBMB4XDTE5
MDIxNDEzMjM0NVoXDTIyMDIxNDEzNTM0NVowejELMAkGA1UEBhMCREsxKTAnBgNVBAoMIEluZ2Vu
IG9yZ2FuaXNhdG9yaXNrIHRpbGtueXRuaW5nMUAwGQYDVQQDDBJUaGVvZG9yYSBMb3JlbnR6ZW4w
IwYDVQQFExxQSUQ6OTIwOC0yMDAyLTItMTUzNTcyMjU4OTU2MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnvY5WimdYyd6EPaka4G5UhqULDlcBKMlYtWChUl5IaCQJQRC2RJuWni3iPP3
2pbifCOmnYrTcO0J+yhqrPo0baR+OgFK35dm5fSfQlkzRRu0OBxBpwzcYkXZmxUGkjPx2YU7zWPr
QCJ5LRkrIPjA1WXDu174aOHk5u15EVlLDPpd2pdL5XP49bfWQcEi4eiDG3ET5V1TGuBn+uPIjiOD
vjjx0Mj4rcVC6NJbVay1qqllRWORF0Ya8zsioaOQHxIr1arRCvoxGnr1GMxfcIzjSwV9+kLkDh8X
dI+dNcEVUzAT9XrxmsUEPz7M6Iqkg/GnI522mPrG62C/XbSwJsx93wIDAQABo4ICyzCCAscwDgYD
VR0PAQH/BAQDAgP4MIGVBggrBgEFBQcBAQSBiDCBhTA8BggrBgEFBQcwAYYwaHR0cDovL29jc3Au
c3lzdGVtdGVzdDIyLnRydXN0MjQwOC5jb20vcmVzcG9uZGVyMEUGCCsGAQUFBzAChjlodHRwOi8v
YWlhLnN5c3RlbXRlc3QyMi50cnVzdDI0MDguY29tL3N5c3RlbXRlc3QyMi1jYS5jZXIwggEgBgNV
HSAEggEXMIIBEzCCAQ8GDSsGAQQBgfRRAgQGAQQwgf0wLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cu
dHJ1c3QyNDA4LmNvbS9yZXBvc2l0b3J5MIHJBggrBgEFBQcCAjCBvDAMFgVEYW5JRDADAgEBGoGr
RGFuSUQgdGVzdCBjZXJ0aWZpa2F0ZXIgZnJhIGRlbm5lIENBIHVkc3RlZGVzIHVuZGVyIE9JRCAx
LjMuNi4xLjQuMS4zMTMxMy4yLjQuNi4xLjQuIERhbklEIHRlc3QgY2VydGlmaWNhdGVzIGZyb20g
dGhpcyBDQSBhcmUgaXNzdWVkIHVuZGVyIE9JRCAxLjMuNi4xLjQuMS4zMTMxMy4yLjQuNi4xLjQu
MIGtBgNVHR8EgaUwgaIwPaA7oDmGN2h0dHA6Ly9jcmwuc3lzdGVtdGVzdDIyLnRydXN0MjQwOC5j
b20vc3lzdGVtdGVzdDIyMS5jcmwwYaBfoF2kWzBZMQswCQYDVQQGEwJESzESMBAGA1UECgwJVFJV
U1QyNDA4MSUwIwYDVQQDDBxUUlVTVDI0MDggU3lzdGVtdGVzdCBYWElJIENBMQ8wDQYDVQQDDAZD
UkwxMTkwHwYDVR0jBBgwFoAUq6gBRBmws0OZ2vp8zNIAGAPnPL8wHQYDVR0OBBYEFAAD/tUIUOz6
8X3hn2o9A8h7QENNMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAFUoS34SlcQxEdHyrLOh
Tq2uxYt1xZcUW7E07nUHcC/ZgWlPdEmnYD0Xr2UYG5WOQgzPO+lBIbwosewgVU+JIrZFIIABobvk
jUFjGKARnw934JbnK1AtsmIxfnN09ZLtwNAhGMl4EXaVx42z2YLDaf5ZEEdlc2qy6kFjBmF3RW2Q
CUdMk5HRj+lTeXNUPAgQqTLS03xCMEHfBnBriH5viA7urN7He2xG3iAA4xqsxYTbm/xsacAne4zB
8MZiEgqtsCQolOs7UWMkh5zlqi/TyPhw8g6cryx5U8HkMDxvLEd6qbgzcS6E9CgDcGI7lq+wpECL
JfrY8F9lC9/drZUyqIU=
</ds:X509Certificate>
</ds:X509Data>
<ds:X509Data>
<ds:X509Certificate>
MIIGSDCCBDCgAwIBAgIES+pulDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJESzESMBAGA1UE
ChMJVFJVU1QyNDA4MSwwKgYDVQQDEyNUUlVTVDI0MDggU3lzdGVtdGVzdCBWSUkgUHJpbWFyeSBD
QTAeFw0xMDA1MTIwODMyMTRaFw0zNzAxMTIwOTAyMTRaME8xCzAJBgNVBAYTAkRLMRIwEAYDVQQK
EwlUUlVTVDI0MDgxLDAqBgNVBAMTI1RSVVNUMjQwOCBTeXN0ZW10ZXN0IFZJSSBQcmltYXJ5IENB
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApuuMpdHu/lXhQ+9TyecthOxrg5hPgxlK
1rpjsyBNDEmOEpmOlK8ghyZ7MnSF3ffsiY+0jA51p+AQfYYuarGgUQVO+VM6E3VUdDpgWEksetCY
Y8L7UrpyDeYx9oywT7E+YXH0vCoug5F9vBPnky7PlfVNaXPfgjh1+66mlUD9sV3fiTjDL12GkwOL
t35S5BkcqAEYc37HT69N88QugxtaRl8eFBRumj1Mw0LBxCwl21GdVY4EjqH1Us7YtRMRJ2nEFTCR
WHzm2ryf7BGd80YmtJeL6RoiidwlIgzvhoFhv4XdLHwzaQbdb9s141q2s9KDPZCGcgIgeXZdqY1V
z7UBCMiBDG7q2S2ni7wpUMBye+iYVkvJD32srGCzpWqG7203cLyZCjq2oWuLkL807/Sk4sYleMA4
YFqsazIfV+M0OVrJCCCkPysS10n/+ioleM0hnoxQiupujIGPcJMA8anqWueGIaKNZFA/m1IKwnn0
CTkEm2aGTTEwpzb0+dCATlLyv6Ss3w+D7pqWCXsAVAZmD4pncX+/ASRZQd3oSvNQxUQr8EoxEULx
Sae0CPRyGwQwswGpqmGm8kNPHjIC5ks2mzHZAMyTz3zoU3h/QW2T2U2+pZjUeMjYhyrReWRbOIBC
izoOaoaNcSnPGUEohGUyLPTbZLpWsm3vjbyk7yvPqoUCAwEAAaOCASowggEmMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgEGMBEGA1UdIAQKMAgwBgYEVR0gADCBrwYDVR0fBIGnMIGkMDqg
OKA2hjRodHRwOi8vY3JsLnN5c3RlbXRlc3Q3LnRydXN0MjQwOC5jb20vc3lzdGVtdGVzdDcuY3Js
MGagZKBipGAwXjELMAkGA1UEBhMCREsxEjAQBgNVBAoTCVRSVVNUMjQwODEsMCoGA1UEAxMjVFJV
U1QyNDA4IFN5c3RlbXRlc3QgVklJIFByaW1hcnkgQ0ExDTALBgNVBAMTBENSTDEwHwYDVR0jBBgw
FoAUI7pMMZDh08zTG7MbWrbIRc3Tg5cwHQYDVR0OBBYEFCO6TDGQ4dPM0xuzG1q2yEXN04OXMA0G
CSqGSIb3DQEBCwUAA4ICAQCRJ9TM7sISJBHQwN8xdey4rxA0qT7NZdKICcIxyIC82HIOGAouKb3o
HjIoMgxIUhA3xbU3Putr4+Smnc1Ldrw8AofLGlFYG2ypg3cpF9pdHrVdh8QiERozLwfNPDgVeCAn
jKPNt8mu0FWBS32tiVM5DEOUwDpoDDRF27Ku9qTFH4IYg90wLHfLi+nqc2HwVBUgDt3tXU6zK4pz
M0CpbrbOXPJOYHMvaw/4Em2r0PZD+QOagcecxPMWI65t2h/USbyO/ah3VKnBWDkPsMKjj5jEbBVR
nGZdv5rcJb0cHqQ802eztziA4HTbSzBE4oRaVCrhXg/g6Jj8/tZlgxRI0JGgAX2dvWQyP4xhbxLN
CVXPdvRV0g0ehKvhom1FGjIz975/DMavkybh0gzygq4sY9Fykl4oT4rDkDvZLYIxS4u1BrUJJJaD
zHCeXmZqOhx8She+Fj9YwVVRGfxT4FL0Qd3WAtaCVyhSQ6SkZgrPvzAmxOUruI6XhEhYGlP5O8WF
ETiATxuZAJNuKMJtibfRhMNsQ+TVv/ZPr5Swe+3DIQtmt1MIlGlTn4k40z4s6gDGKiFwAYXjd/kI
D32R/hJPE41o9+3nd8aHZhBy2lF0jKAmr5a6Lbhg2O7zjGq7mQ3MceNeebuWXD44AxIinryzhqnE
WI+BxdlFaia3U7o2+HYdHw==
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
<ds:Object xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"" xmlns:openoces=""http://www.openoces.org/2006/07/signature#"" Id=""ToBeSigned""><ds:SignatureProperties>
<ds:SignatureProperty Target=""signature""><openoces:Name>RequestIssuer</openoces:Name><openoces:Value Encoding=""base64"" VisibleToSigner=""yes"">Tm9ibHk=</openoces:Value></ds:SignatureProperty>
<ds:SignatureProperty Target=""signature""><openoces:Name>challenge</openoces:Name><openoces:Value Encoding=""xml"" VisibleToSigner=""no"">2993001065895448039</openoces:Value></ds:SignatureProperty>
<ds:SignatureProperty Target=""signature""><openoces:Name>TimeStamp</openoces:Name><openoces:Value Encoding=""base64"" VisibleToSigner=""no"">MjAxOS0wMi0xNCAxNDozMzoxOCswMDAw</openoces:Value></ds:SignatureProperty>
<ds:SignatureProperty Target=""signature""><openoces:Name>action</openoces:Name><openoces:Value Encoding=""xml"" VisibleToSigner=""no"">logon</openoces:Value></ds:SignatureProperty>
</ds:SignatureProperties></ds:Object>
</ds:Signature></openoces:signature>";
        private static string challenge = "2993001065895448039";
        /// <summary>
        /// Tests if the environment has been setup correctly.
        /// </summary>
        /// <param name="args">none - reacts on user input</param>
        public static void Main(string[] args)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json");

            Configuration = builder.Build();
            ServiceProvider = BuildDi();

            MainAsync(args).GetAwaiter().GetResult();

        }

        private static IServiceProvider BuildDi()
        {
            var services = new ServiceCollection();

            services.AddSingleton<ILoggerFactory, LoggerFactory>();
            services.AddSingleton(typeof(ILogger<>), typeof(Logger<>));
            services.AddLogging((builder) => builder.SetMinimumLevel(LogLevel.Trace));

            services.AddScoped<IConfigurationChecker, ConfigurationChecker>();
            services.AddScoped<ICrlDistributionPointsExtractor, CrlDistributionPointsExtractor>();
            services.AddScoped<ICaCrlRevokedChecker, FullCrlRevocationChecker>();
            services.AddScoped<IRevocationChecker, FullCrlRevocationChecker>();
            services.AddScoped<IEnvironments, Environments>();
            services.AddScoped<IX509CertificatePropertyExtrator, X509CertificatePropertyExtrator>();
            services.AddScoped<IPidService, PidService>();
            services.AddScoped<IOcspAliveTester, OcspAliveTester>();
            services.AddScoped<IPidAlivetester, PidAlivetester>();
            services.AddScoped<IRidAliveTester, RidAliveTester>();
            services.AddScoped<IRootCertificates, RootCertificates>();
            services.AddScoped<ICertificateRevocationHandler, CertificateRevocationHandler>();
            services.AddScoped<ILdapFactory, LdapFactory>();
            services.AddScoped<IProperties, Properties>();
            services.AddScoped<IOcspAliveTester, OcspAliveTester>();
            services.AddScoped<IHttpCrlDownloader, HttpCrlDownloader>();

            services.AddScoped<IRequestGenerator, RequestGenerator>();
            services.AddScoped<IRequester, Requester>();
            services.AddScoped<TimeService, CurrentTimeTimeService>();
            services.AddScoped<IX509CrlVerifyImpl, X509CrlVerifyImpl>();
            services.AddScoped<IEnvironmentUtil, EnvironmentUtil>();
            services.AddScoped<IRidService, RidService>();
            services.AddScoped<IHttpClient, HttpClient>();

            services.AddScoped<ILogonHandler, LogonHandler>();
            services.AddScoped<IServiceProviderSetup, ServiceProviderSetup>();
            services.AddScoped<IErrorCodeChecker, ErrorCodeChecker>();
            services.AddScoped<IChallengeVerifier, ChallengeVerifier>();
            services.AddScoped<IOpensignSignatureFactory, OpensignSignatureFactory>();
            services.AddScoped<IOcesCertificateFactory, OcesCertificateFactory>();
            services.AddScoped<IChainVerifier, ChainVerifier>();
            services.AddScoped<ILdapCrlDownloader, LdapCrlDownloader>();
            services.AddScoped<IXmlUtil, XmlUtil>();

            services.AddScoped<IClientConfiguration, ClientConfiguration>(provider =>
                new ClientConfiguration()
                {
                    WsUrl = _wsUrl,
                    PfxFile = _pfxFile,
                    PfxPassword = _pfxPassword
                });
            var serviceProvider = services.BuildServiceProvider();
            return serviceProvider;
        }

        public static async Task MainAsync(string[] args)
        {
            await PrintLineAsync("OOAPI environment tester\n---------------------------\n");
            X509Certificate2 cert = await GetCertificateAsync();

            await PrintEnviromentListAsync();

            await SetEnviroment(await PromptAsync());
            
            if (await AskYesNoAsync("Ping LDAP?"))
            {
                await PingLdapAsync();
            }

            if (await AskYesNoAsync("Ping PID service?"))
            {
               await PingPidAsync();
            }

            if (await AskYesNoAsync("Ping RID service?"))
            {
                await PingRidAsync();
            }

            if (await AskYesNoAsync("Ping OCSP service?"))
            {
                await PingOcspAsync(cert);
            }

            if (await AskYesNoAsync("Ping CRL service?"))
            {
                await PingCrlsAsync(cert);
            }
            if (await AskYesNoAsync("Verify Extract data services?"))
            {
                await ExtractData();
            }
            await PrintLineAsync("\n\n---------------------------\n");

            await PrintLineAsync("\n\n The End. Press <ENTER> to quit.\n");

            Console.ReadLine();
        }
        static async Task<X509Certificate2> GetCertificateAsync()
        {
            String certificatePath = _pfxFile;

            await PrintLineAsync("\n\n Certificate used for test is stored within: " + certificatePath + ".");
            await PrintLineAsync("\n\n Press <ENTER> to continue.\n");

            Console.ReadLine();

            String certificatePassword = _pfxPassword;

            return new X509Certificate2(certificatePath, certificatePassword);

        }


        static async Task<X509Certificate2> FindCertificateToUseAsync()
        {
            
            String defaultCertificatePath = _pfxFile;
            
            String defaultCertificatePassword = _pfxPassword;

            await PrintLineAsync("\n\n Enter path to certificate. (Default: " + defaultCertificatePath +")\n");
            String pathToCertificate = await PromptAsync();
            if (pathToCertificate.Length == 0)
            {
                pathToCertificate = defaultCertificatePath;
            }

            await PrintLineAsync("\n\n Enter password to certificate (Default: " + defaultCertificatePassword + ")\n");
            String certPassword = await PromptMaskAsync();
            if (certPassword.Length == 0)
            {
                certPassword = defaultCertificatePassword;
            }
            if (!File.Exists(pathToCertificate) || !Path.HasExtension(pathToCertificate))
            {
                await PrintLineAsync("\nCould not find valid certificate\n");
                return null;
            }

            return new X509Certificate2(pathToCertificate, certPassword);
            
        }

        static Dictionary<string, OcesEnvironment> CreateEnvDictionaryAsync()
        {
            var ocesEnvironments = new Dictionary<string, OcesEnvironment>
                                       {
                                           {"1", OcesEnvironment.OcesII_DanidEnvPreprod},
                                           {"2", OcesEnvironment.OcesII_DanidEnvProd}
                                       };
            return ocesEnvironments;
        }

        static Task PrintEnviromentListAsync()
        {
            Console.WriteLine("Set enviroment by entering an appropriate number. Certificate used for the test must originate from this environment:\n");

            foreach (var key in EnvDictionary.Keys.OrderBy(k => int.Parse(k)))
            {
                Console.WriteLine(key + " = " + EnvDictionary[key]);
            }
            return Task.CompletedTask;
            
        }

        private static async Task SetEnviroment(string value)
        {
            var currentenv = EnvDictionary[value];
            var environments = ServiceProvider.GetRequiredService<IEnvironments>();
            await environments.OcesEnvironments(new List<OcesEnvironment>()
            {
                currentenv
            });
        }

        static async Task PingLdapAsync()
        {
            try
            {
                var configurationChecker = ServiceProvider.GetRequiredService<IConfigurationChecker>();
                await configurationChecker.VerifyRootCertificateFromLdapAsync();
                await PrintLineAsync("Success");
            }
            catch (Exception e)
            {
                Console.Write("Calling LDAP failed" + e.Message);
            }
        }
        static async Task ExtractData()
        {
            try
            {
                var logonHandler = ServiceProvider.GetRequiredService<ILogonHandler>();
                await logonHandler.ValidateAndExtractCertificateAndStatus(loginData, challenge, _logOnto);
                await PrintLineAsync("Success");
            }
            catch (Exception e)
            {
                Console.Write("Calling LDAP failed" + e.Message);
            }
        }
        static async Task PingPidAsync()
        {
            try
            {
                var configurationChecker = ServiceProvider.GetRequiredService<IConfigurationChecker>();
                await configurationChecker.VerifyPidServiceAsync();
                await PrintLineAsync("Success");
            }
            catch (Exception e)
            {
                Console.Write("Calling PID service failed " + e.Message);
            }
        }

        static async Task PingRidAsync()
        {
            try
            {
                var configurationChecker = ServiceProvider.GetRequiredService<IConfigurationChecker>();
                await configurationChecker.VerifyRidServiceAsync();
                await PrintLineAsync("Success");
            }
            catch (Exception e)
            {
                Console.Write("Calling PID service failed " + e.Message);
            }
        }

        static async Task PingCrlsAsync(X509Certificate2 certificate)
        {
            var crlDistributionPointsExtractor = ServiceProvider.GetRequiredService<ICrlDistributionPointsExtractor>();
            var extractCrlDistributionPoints = await crlDistributionPointsExtractor.ExtractCrlDistributionPointsAsync(certificate);

            var caCrlRevokedChecker = ServiceProvider.GetRequiredService<ICaCrlRevokedChecker>();
            Crl crl = await caCrlRevokedChecker.DownloadCrl(extractCrlDistributionPoints.CrlDistributionPoint);
            if (await crl.IsValid())
            {
                await PrintLineAsync("Success");
            }
            else
            {
                await PrintLineAsync("Invalid CRL retrieved");
            }

        }

        static Task<string> FindOcspUrlInCertificateAsync(X509Certificate2 cert)
        {
            var x509CertificatePropertyExtrator =
                ServiceProvider.GetRequiredService<IX509CertificatePropertyExtrator>();
            return x509CertificatePropertyExtrator.GetOcspUrl(cert);
        }

        static async Task PingOcspAsync(X509Certificate2 cert)
        {
            try
            {
                var ocspUrl = await FindOcspUrlInCertificateAsync(cert);
                var configurationChecker = ServiceProvider.GetRequiredService<IConfigurationChecker>();
                if (await configurationChecker.CanCallOcspAsync(ocspUrl))
                {
                    await PrintLineAsync("Success");
                }
                else
                {
                    await PrintLineAsync("Could not call OCSP");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error calling OCSP");
                Console.WriteLine(e.StackTrace);
            }
        }

        static async Task<bool> AskYesNoAsync(string question)
        {
            await PrintLineAsync("\n\n" + question + "\n---------------------------\ny/n[n]");
            return await PromptAsync() == "y";
        }

        static Task<string> PromptAsync()
        {
            PrintAsync("> ");
            return Task.FromResult(Console.ReadLine());
        }

        static Task<string> PromptMaskAsync()
        {
            int chr = 0;
            string pass = "";
            const int ENTER = 13;
            Boolean proceed = true;

            while (proceed) { 
                chr = Console.ReadKey(true).KeyChar;
                if (chr == ENTER)
                {
                    proceed = false;                        
                }
                else
                {
                    pass += (char)chr;
                }                
            } 

            return Task.FromResult(pass);
        }

        static Task PrintAsync(string s)
        {
            Console.Write(s);
            return Task.CompletedTask;
        }

        static Task PrintLineAsync(string line)
        {
            Console.WriteLine(line);
            return Task.CompletedTask;
        }
    }
}
