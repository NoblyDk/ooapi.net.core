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
using org.openoces.ooapi.environment;
using org.openoces.ooapi.ldap;
using org.openoces.ooapi.pidservice;
using org.openoces.ooapi.ping;
using org.openoces.ooapi.ridservice;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.utils.ocsp;
using org.openoces.ooapi.validation;
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
        private static string _logOnto = "";
        private static string _wsUrl = "https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidws/";
        private static string _pfxFile = "";
        private static string _pfxPassword = "";

        private static string loginData = "";
        private static string challenge = "";
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
