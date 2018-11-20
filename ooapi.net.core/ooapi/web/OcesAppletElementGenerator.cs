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

using System.Collections.Specialized;
using System.Net;
using System.Threading.Tasks;


namespace org.openoces.ooapi.web
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;
    using org.openoces.securitypackage;
    public class OcesAppletElementGenerator
    {
        private readonly ISigner _signer;
        private readonly ISignHandler _signHandler;
        private string _serverUrlPrefix;
        private const string AppletClass = "dk.pbs.applet.bootstrap.BootApplet";
        private const string SignHeight = "450";
        private const string SignWidth = "500";
        private const string LogonHeight = "250";
        private const string LogonWidth = "200";
        public  string DigestParameter = "paramsdigest";

        public  string SignatureParameter = "signeddigest";

        private readonly Dictionary<string, string> _signedParameters = new Dictionary<string, string>();
        private readonly Dictionary<string, string> _unsignedParameters = new Dictionary<string, string>();

       
        private  String _returnUrl;

        public OcesAppletElementGenerator(ISigner signer, ISignHandler signHandler)
        {
            _signer = signer;
            _signHandler = signHandler;
        }

        public Task AddReturnUrl(String returnUrl)
        {
            _returnUrl = returnUrl;
            return Task.CompletedTask;
        }

        public Task AddServerUrlPrefix(string serverUrlPrefix)
        {
            _serverUrlPrefix = serverUrlPrefix;
            return Task.CompletedTask;
        }

        public Task<string> GenerateSignAppletElement(string formAction, string pfxFile, string pfxPassword)
        {
            return GenerateAppletElement(formAction, true, pfxFile, pfxPassword);
        }

        public Task<string> GenerateLogonAppletElement(string formAction, string pfxFile, string pfxPassword)
        {
            return GenerateAppletElement(formAction, false, pfxFile, pfxPassword);
        }

        public async Task SetChallenge(string challenge)
        {
            await AddSignedParameter("signproperties", "challenge=" + challenge);
        }

        public async Task SetLogLevel(string logLevel)
        { 
            await AddSignedParameter("log_level", logLevel); // INFO/DEBUG/ERROR
        }

        public async Task SetSignText(string signText, string format)
        {
            await AddSignedParameter("signtext", await _signHandler.Base64Encode(signText));
            await AddSignedParameter("signtextformat", format);

        }

        private async Task<string> GenerateAppletElement(string formAction, bool sign, string pfxFile, string pfxPassword)
        {
            await AddSignedParameter("paramcert", await _signer.GetCertificateAsync(pfxFile, pfxPassword));
            await AddParameters(sign);

            byte[] normalizedParameters = await GetNormalizedParameters();
            byte[] parameterDigest = await CalculateDigest(normalizedParameters);
            byte[] parameterSignature = await _signer.CalculateSignatureAsync(normalizedParameters, pfxFile, pfxPassword);

            string digestString = await Base64Encode(parameterDigest);
            string signatureString = await Base64Encode(parameterSignature);

            var sb = new StringBuilder();
            // Create a unique path to the applet, to prevent caching in the applet loader
            string appletPath = _serverUrlPrefix + "/bootapplet/" + new TimeSpan(DateTime.Now.Ticks).Ticks;
            sb.Append("<applet "
                      + " name=\"DANID_DIGITAL_SIGNATUR\" tabindex=\"1\" "
                      + "archive=\"" + appletPath
                      + "\" code=\"" + AppletClass
                      + "\" WIDTH=\"" + (sign ? SignWidth : LogonWidth)
                      + "\" HEIGHT=\"" + (sign ? SignHeight : LogonHeight)
                      + "\" mayscript=\"mayscript\""
                      + ">\n");

            foreach (var parameter in _signedParameters)
            {
                sb.Append(await ToAppParamsTag(parameter));
            }

            sb.Append("<param name=\"" + DigestParameter + "\" value=\"" + digestString + "\" />\n");
            sb.Append("<param name=\"" + SignatureParameter + "\" value=\"" + signatureString + "\" />\n");

            foreach (var parameter in _unsignedParameters)
            {
                sb.Append(await ToAppParamsTag(parameter));
            }

            sb.Append("</applet>\n");
            sb.Append(await GetJavascript(formAction, sign));
            return sb.ToString();
        }

        private Task<string> Base64Encode(byte[] bytes)
        {
            return Task.FromResult(Convert.ToBase64String(bytes));
        }

        private Task<string> GetJavascript(string formAction, bool sign)
        {
            string infix = sign ? "Sign" : "Logon";
            var html = new StringBuilder();
            html.Append("<form name=\"signedForm\" method=\"post\" action=\"" + formAction + "\">\r\n" +
                        "        <input type=\"hidden\" name=\"signature\" />\r\n" +
                        "        <input type=\"hidden\" name=\"result\" />\r\n");

            if(_returnUrl!=null && ! "".Equals(_returnUrl))
            {
                html.Append("        <input type=\"hidden\" name=\"ReturnUrl");
                html.Append("\" value=\"");
                html.Append(WebUtility.HtmlEncode(_returnUrl));
                html.Append("\">\r\n");
            }

            html.Append("</form>\r\n" +
                        "\r\n" +
                        "<script type=\"text/javascript\">\r\n" +
                        "        function on" + infix + "Ok(signature) {\r\n" +
                        "            document.signedForm.signature.value=signature;\r\n" +
                        "            document.signedForm.result.value='ok';\r\n" +
                        "            document.signedForm.submit();\r\n" +
                        "        }\r\n" +
                        "        function on" + infix + "Cancel(msg) {\r\n" +
                        "            document.signedForm.result.value=msg;\r\n" +
                        "            document.signedForm.submit();\r\n" +
                        "        }\r\n" +
                        "        function on" + infix + "Error(msg) {\r\n" +
                        "            document.signedForm.result.value=msg;\r\n" +
                        "            document.signedForm.submit();\r\n" +
                        "        }\r\n" +
                        "</script>");
            return Task.FromResult(html.ToString());
        }

        private Task<string> ToAppParamsTag(KeyValuePair<string, string> entry)
        {
            return Task.FromResult("<param name=\"" + entry.Key + "\" value=\"" + entry.Value + "\" />\n");
        }

        private Task AddParameters(bool sign)
        {
            AddSignedParameter("ZIP_FILE_ALIAS", sign ? "OpenSign2" : "OpenLogon2");
            AddSignedParameter("ZIP_BASE_URL", _serverUrlPrefix);
            AddSignedParameter("ServerUrlPrefix", _serverUrlPrefix);
            AddUnsignedParameter("MAYSCRIPT", "true");
            return Task.CompletedTask;
        }

        public Task AddSignedParameter(string key, string value)
        {
            _signedParameters.Add(key, value);
            return Task.CompletedTask;
        }

        public Task AddUnsignedParameter(string key, string value)
        {
            _unsignedParameters.Add(key, value);
            return Task.CompletedTask;
        }

        protected Task<byte[]> CalculateDigest(byte[] data)
        {
            var sha = SHA256.Create();
            byte[] digest = sha.ComputeHash(data);
            return Task.FromResult(digest);
        }

        protected Task<byte[]> GetNormalizedParameters()
        {
            var sb = new StringBuilder();
            var sortedParameters = new SortedDictionary<string, string>(_signedParameters);

            foreach (var entry in sortedParameters)
            {
                sb.Append(entry.Key.ToLower() + entry.Value);
            }
            return Task.FromResult(Encoding.UTF8.GetBytes(sb.ToString()));
        }
    }
}