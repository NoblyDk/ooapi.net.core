# ooapi.net.core
NemID Implementation done with dotnet standard and async/await Task.


Version 2.0.0

Changed the HttpsBinding to a custom one, to fix the ExpectContinue (Http 100 Continue) error on .NET Core framework. the package should now work on .NET Core

Pre-Version 2.0.0 ->

OBS:
Does not work in DotNetCore 2.1 - See Issue https://github.com/dotnet/wcf/issues/3048

You can still have it working on ASPNET Core but you have to Target Full .NET Framework until the issue is solved.

-
-
-
-


This is by all means a free and untested conversion of the original code, i have only done what anyone else can do, take NemId's implementation example and converted it from static code to Task based with interfaces. it makes it easier to use in a modern webapplication and easier to unit test, and the use of DI to supply the components needed.

-
-
-
-
-

My own test-implementation:

i have a ServiceCollectionExtension with the following Extension:

        public static void AddNemId(this IServiceCollection services)
        {
            services.AddScoped<IErrorCodeChecker, ErrorCodeChecker>();
            services.AddScoped<IXmlUtil, XmlUtil>();
            services.AddScoped<IProperties, Properties>();
            services.AddScoped<ILdapFactory, LdapFactory>();
            services.AddScoped<ILdapCrlDownloader, LdapCrlDownloader>();
            services.AddScoped<IX509CertificatePropertyExtrator, X509CertificatePropertyExtrator>();
            services.AddScoped<IChainVerifier, ChainVerifier>();
            services.AddScoped<IOcesCertificateFactory, OcesCertificateFactory>();
            services.AddScoped<IOpensignSignatureFactory, OpensignSignatureFactory>();
            services.AddScoped<IChallengeVerifier, ChallengeVerifier>();
            services.AddScoped<IX509CrlVerifyImpl, X509CrlVerifyImpl>();
            services.AddScoped<IHttpClient, org.openoces.ooapi.utils.HttpClient>();
            services.AddScoped<TimeService, CurrentTimeTimeService>();
            services.AddScoped<IHttpCrlDownloader, HttpCrlDownloader>();
            services.AddScoped<ICrlDistributionPointsExtractor, CrlDistributionPointsExtractor>();
            services.AddScoped<IRevocationChecker, FullCrlRevocationChecker>();
            services.AddScoped<IRootCertificates, RootCertificates>();
            services.AddScoped<IEnvironments, Environments>();
            services.AddScoped<IServiceProviderSetup, ServiceProviderSetup>();
            services.AddScoped<IEnvironmentUtil, EnvironmentUtil>();
            services.AddScoped<ILogonHandler, LogonHandler>();
            services.AddScoped<IPidService, PidService>();
            services.AddScoped<ISigner, Signer>();
            services.AddScoped<IJSONParametersGenerator, JSONParametersGenerator>();
            services.AddScoped<ISignHandler, SignHandler>();
            services.AddScoped<INemIdService, NemIdService>();
        }

Using the NemId components is recommended in a service style:

    public interface INemIdService
    {
        Task<(string parameters, string challenge)> GenerateParameters();
        Task<(string parameters, string challenge, string signText)> GenerateParameters(byte[] signText);
        Task<string> ExtractData(string result, string signature, string challenge);
        Task<(Dictionary<string, string> errors, byte[] signedContent)> ExtractData(string result, string signature, string challenge, string signText);
        Task<bool> Match(string pid, string cpr);
        Task<string> GetCpr(string pid);
    }

Implementing the INemIdService can look something like this:

       public class NemIdService : INemIdService
        {
        private readonly IPidService _pidService;
        private readonly ISigner _signer;
        private readonly ISignHandler _signHandler;
        private readonly ILogonHandler _logonHandler;
        private readonly ICertificateConfiguration _certificateConfiguration;
        private readonly IJSONParametersGenerator _jsonParametersGenerator;

        public NemIdService(
            IPidService pidService,
            ISigner signer,
            ISignHandler signHandler,
            ILogonHandler logonHandler,
            ICertificateConfiguration certificateConfiguration,
            IJSONParametersGenerator jsonParametersGenerator)
        {
            _pidService = pidService;
            _signer = signer;
            _signHandler = signHandler;
            _logonHandler = logonHandler;
            _certificateConfiguration = certificateConfiguration;
            _jsonParametersGenerator = jsonParametersGenerator;
        }
        
        
            public async Task<(string parameters, string challenge)> GenerateParameters()
            {
            var timestamp = await _signHandler.Base64Encode(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss+0000"));
            var challenge = GenerateChallenge();
            var props = "challenge=" + challenge + ";";

            await _jsonParametersGenerator.SetParameter("SP_CERT", await _signer.GetCertificateAsync(_certificateConfiguration.PfxFilePath, _certificateConfiguration.Password));
            await _jsonParametersGenerator.SetParameter("clientflow", "OcesLogin2");
            await _jsonParametersGenerator.SetParameter("timestamp", timestamp);
            await _jsonParametersGenerator.SetParameter("SIGN_PROPERTIES", props);

            var parameters = await _jsonParametersGenerator.GenerateParameters(_certificateConfiguration.PfxFilePath, _certificateConfiguration.Password);

            return (parameters, challenge);
        }

        public async Task<(string parameters, string challenge, string signText)> GenerateParameters(byte[] signText)
        {
            var timestamp = await _signHandler.Base64Encode(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss+0000"));
            var challenge = GenerateChallenge();
            var props = "challenge=" + challenge + ";";
            var encodedSignText = await _signHandler.Base64Encode(signText);

            await _jsonParametersGenerator.SetParameter("SP_CERT", await _signer.GetCertificateAsync(_certificateConfiguration.PfxFilePath, _certificateConfiguration.Password));
            await _jsonParametersGenerator.SetParameter("clientflow", "OcesLogin2");
            await _jsonParametersGenerator.SetParameter("timestamp", timestamp);
            await _jsonParametersGenerator.SetParameter("SIGNTEXT_FORMAT", "PDF");
            await _jsonParametersGenerator.SetParameter("SIGN_PROPERTIES", props);
            await _jsonParametersGenerator.SetParameter("signtext", encodedSignText);


            var parameters = await _jsonParametersGenerator.GenerateParameters(_certificateConfiguration.PfxFilePath, _certificateConfiguration.Password);

            return (parameters, challenge, encodedSignText);
        }
        

        public Task<string> GetCpr(string pid)
        {
            return _pidService.LookupCprAsync(pid, _certificateConfiguration.SPID);
        }
        
        
        public Task<bool> Match(string pid, string cpr)
        {
            return _pidService.MatchAsync(cpr, pid, _certificateConfiguration.SPID);
        }
        
        public async Task<string> ExtractData(string result, string signature, string challenge)
        {
           
            if (string.IsNullOrEmpty(result))
            {
                result = "CAN002";
            }
            else if ("ok" != result.ToLower())
            {
                result = await _signHandler.Base64Decode(result);
            }

            if (result.ToLower() != "ok") throw new Exception(ErrorHandler.ErrorCodes[$"{result}.text"]);
            try
            {
                var loginData = await _signHandler.Base64Decode(signature);
                var certificateAndStatus = await _logonHandler.ValidateAndExtractCertificateAndStatus(loginData, challenge, _certificateConfiguration.LogonTo);
                if (!(certificateAndStatus.Certificate is PocesCertificate pocesCert))
                    throw new Exception($"Not Poces");
                var status = certificateAndStatus.CertificateStatus;
                if (status == CertificateStatus.Valid)
                {
                    return pocesCert.Pid;
                }

                ErrorHandler.ErrorCodes.TryGetValue($"certificate.{status}", out var cerErrorText);
                throw new Exception($"Certifikatet er {cerErrorText}");
            }
            catch (NonOcesCertificateException)
            {
                throw new Exception($"Ikke et OCES-certifikat");
            }
        }
        
        
        public async Task<(Dictionary<string, string> errors, byte[] signedContent)> ExtractData(string result, string signature, string challenge, string signText)
        {
            var dic = new Dictionary<string, string>();

            if (string.IsNullOrEmpty(result))
            {
                result = "CAN002";
            }
            else if ("ok" != result.ToLower())
            {
                result = await _signHandler.Base64Decode(result);
            }

            if (result.ToLower() == "ok")
            {
                try
                {
                    var status = await _signHandler.validateSignatureAgainstAgreementPDF(signature, signText, challenge, _certificateConfiguration.LogonTo);
                    if (!(status.Certificate is PocesCertificate))
                    {
                        dic.Add("errorText",
                            $"Det benyttede certifikat er ikke af korrekt type. Forventede personligt certifikat, fik {GetErrorText(status.Certificate)}");
                    }
                    else if (status.CertificateStatus != CertificateStatus.Valid)
                    {
                        ErrorHandler.ErrorCodes.TryGetValue($"certificate.{status.CertificateStatus}", out var cerErrorText);
                        dic.Add("errorDescription", status.CertificateStatus.ToString());
                        dic.Add("errorText", $"Certifikatet er {cerErrorText}");
                    }
                    else if (status.SignatureMatches)
                    {
                        var signedContent = status.Signature.SignedDocument.SignedContent;
                        return (dic, signedContent);
                    }
                }
                catch (NonOcesCertificateException)
                {
                    dic.Add("errorText", "Ikke et OCES-certifikat");
                }
                catch (Exception ex)
                {
                    dic.Add("errorText", "Ukendt fejl: " + ex.Message);
                }
            }
            else
            {
                dic.Add("errorDescription", ErrorHandler.ErrorCodes[$"{result}.description"]);
                dic.Add("errorText", ErrorHandler.ErrorCodes[$"{result}.text"]);
            }

            return (dic, null);
        }
        
        private string GetErrorText(OcesCertificate cert)
        {
            if (cert is PocesCertificate)
            {
                return ErrorHandler.ErrorCodes["certificateTypes.poces"];
            }
            if (cert is MocesCertificate)
            {
                return ErrorHandler.ErrorCodes["certificateTypes.moces"];
            }
            if (cert is VocesCertificate)
            {
                return ErrorHandler.ErrorCodes["certificateTypes.voces"];
            }
            if (cert is FocesCertificate)
            {
                return ErrorHandler.ErrorCodes["certificateTypes.foces"];
            }
            return ErrorHandler.ErrorCodes["certificateTypes.unknown"];
        }
        
        private RandomNumberGenerator _random = new RNGCryptoServiceProvider();
        private string GenerateChallenge()
        {
            var randomBytes = new byte[8];
            _random.GetNonZeroBytes(randomBytes);
            long randomLong = BitConverter.ToInt64(randomBytes, 0);
            return "" + randomLong;
        }


You are welcome to read NemId's Implementation guides and the original sourcecode from NemId.

