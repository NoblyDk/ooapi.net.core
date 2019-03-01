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
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.signatures;
using org.openoces.ooapi.validation;
using org.openoces.serviceprovider;
using org.openoces.ooapi.certificate;
using Org.BouncyCastle.Crypto.Digests;
using Microsoft.Extensions.Logging;

namespace org.openoces.securitypackage
{
    /// <summary>
    /// This class handles validation and extraction of person ID from the output data provided by the Open Sign applet. 
    /// </summary>
    public class SignHandler : ISignHandler
    {
        private readonly ILogger<SignHandler> logger;
        private readonly IServiceProviderSetup _serviceProviderSetup;
        private readonly IChallengeVerifier _challengeVerifier;
        private readonly IOpensignSignatureFactory _opensignSignatureFactory;

        public SignHandler(ILogger<SignHandler> logger, IServiceProviderSetup serviceProviderSetup, IChallengeVerifier challengeVerifier, IOpensignSignatureFactory opensignSignatureFactory)
        {
            this.logger = logger;
            _serviceProviderSetup = serviceProviderSetup;
            _challengeVerifier = challengeVerifier;
            _opensignSignatureFactory = opensignSignatureFactory;
        }
        /// <summary>
        /// Given the output data from the Open Sign applet, signed text is extracted if the login data is valid.
        /// </summary>
        /// <param name="loginData">the output data from the Open Sign applet (base64 encoded).</param>
        /// <param name="agreement">the string to match against the signed text in the login data.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or 
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended)</param>.
        /// <returns>true if the signed text matches the agreement parameter</returns>
        /// <throws>AppletException in case the applet returned an error code.</throws>
        public async Task<SignatureValidationStatus> ValidateSignatureAgainstAgreement(string loginData, string agreement, string stylesheet, string challenge, string logonto)
        {           
            var errorCodeChecker = new ErrorCodeChecker();
            if (await errorCodeChecker.HasError(loginData))
            {
                throw new AppletException(await errorCodeChecker.ExtractError(loginData));
            }
            logger.LogDebug("CreateOpensignSignature");
            var opensignSignature = await CreateOpensignSignature(await Base64Decode(loginData));
            logger.LogDebug("Done CreateOpensignSignature");
            logger.LogDebug("ValidateSignatureParameters");
            await ValidateSignatureParameters(opensignSignature, challenge, logonto);
            logger.LogDebug("Done ValidateSignatureParameters");
            logger.LogDebug("EncodeSignature");
            var encodedSignature = await EncodeSignature(opensignSignature);
            logger.LogDebug("Done EncodeSignature");
            var certificate = opensignSignature.SigningCertificate;
            logger.LogDebug("ValidityStatus");
            CertificateStatus status = await certificate.ValidityStatus();
            logger.LogDebug("Done ValidityStatus");
            logger.LogDebug("IsRevoked");
            if (await _serviceProviderSetup.CurrentChecker.IsRevoked(certificate))
            {
                status = CertificateStatus.Revoked;
            }
            logger.LogDebug("Done IsRevoked");
            logger.LogDebug("SignatureMatches");
            var signatureMatches = await SignatureMatches(encodedSignature, agreement, stylesheet, opensignSignature);
            logger.LogDebug("Done SignatureMatches");
            logger.LogDebug("GetSignatureProperty");
            SignatureProperty ruidProperty = await GetSignatureProperty(opensignSignature, "rememberUseridToken");
            logger.LogDebug("Done GetSignatureProperty");
            string ruidToken = (ruidProperty == null ? null : ruidProperty.Value);
            return new SignatureValidationStatus(opensignSignature, status, signatureMatches, ruidToken);
        }

        private Task<Boolean> SignatureMatches(string encodedSignature, string encodedAgreement, string signTextTransformation, OpensignSignature opensignSignature)
        {          
            if (!encodedAgreement.Equals(encodedSignature))
            {               
                return Task.FromResult(false);
            }

            var stylesheetDigest = opensignSignature.StylesheetDigest;
            if (stylesheetDigest != null)
            {
                if (signTextTransformation == null)
                {
                    throw new ArgumentException("signTextTransformation is required for XML signing");
                }

                byte[] stylesheetBytes = Encoding.UTF8.GetBytes(signTextTransformation);

                Sha256Digest digester = new Sha256Digest();
                digester.BlockUpdate(stylesheetBytes, 0, stylesheetBytes.Length);
                byte[] result = new byte[digester.GetDigestSize()];
                digester.DoFinal(result, 0);
                var calculatedDigest = Convert.ToBase64String(result);             
                return Task.FromResult(stylesheetDigest.Equals(calculatedDigest));
            }         
            return Task.FromResult(true);
        }


        public Task<SignatureValidationStatus> ValidateSignatureAgainstAgreement(string loginData, string agreement, string challenge, string logonto)
        {
            return ValidateSignatureAgainstAgreement(loginData, agreement, null, challenge, logonto);
        }

        public async Task<SignatureValidationStatus> validateSignatureAgainstAgreementPDF(String loginData, String encodedAgreement, String challenge, String logonto)
        {
            var errorCodeChecker = new ErrorCodeChecker();
            if (await errorCodeChecker.HasError(loginData))
            {
                throw new AppletException(await errorCodeChecker.ExtractError(loginData));
            }
            logger.LogDebug("CreateOpensignSignature");
            var opensignSignature = await CreateOpensignSignature(await Base64PDFDecode(loginData));
            logger.LogDebug("Done CreateOpensignSignature");
            logger.LogDebug("ValidateChallenge");
            await ValidateChallenge(opensignSignature, challenge);
            logger.LogDebug("Done ValidateChallenge");
            if (logonto != null)
            {
                logger.LogDebug("ValidateLogonto");
                await ValidateLogonto(opensignSignature, logonto);
                logger.LogDebug("Done ValidateLogonto");
            }

            String encodedSignature = await Base64Encode(opensignSignature.SignedDocument.SignedContent);

            var certificate = opensignSignature.SigningCertificate;
            logger.LogDebug("ValidityStatus");
            CertificateStatus status = await certificate.ValidityStatus();
            logger.LogDebug("Done ValidityStatus");
            logger.LogDebug("IsRevoked");
            if (await _serviceProviderSetup.CurrentChecker.IsRevoked(certificate))
            {
                status = CertificateStatus.Revoked;
            }
            logger.LogDebug("Done IsRevoked");
            logger.LogDebug("SignatureMatches");
            var signatureMatches = await SignatureMatches(encodedSignature, encodedAgreement, null, opensignSignature);
            logger.LogDebug("Done SignatureMatches");
            //@FIXME HER MANGLER CHECK AF ATTACHMENTS !
            logger.LogDebug("GetSignatureProperty");
            SignatureProperty ruidProperty = await GetSignatureProperty(opensignSignature, "rememberUseridToken");
            logger.LogDebug("Done GetSignatureProperty");
            string ruidToken = (ruidProperty == null ? null : ruidProperty.Value);
            return new SignatureValidationStatus(opensignSignature, status, signatureMatches, ruidToken);
        }

        public Task<string> Base64Encode(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            return Task.FromResult(Convert.ToBase64String(bytes));
        }

        public Task<string> Base64Encode(byte[] data)
        {
            return Task.FromResult(Convert.ToBase64String(data));
        }

        public Task<string> Base64Decode(string s)
        {
            logger.LogDebug("Base64Decode");
            var bytes = Convert.FromBase64String(s);
            var resultString = Encoding.UTF8.GetString(bytes);
            logger.LogDebug("Done Base64Decode");
            return Task.FromResult(resultString);
        }

        public Task<string> Base64PDFDecode(string s)
        {
            var bytes = Convert.FromBase64String(s);
            return Task.FromResult(Encoding.ASCII.GetString(bytes));
        }

        private async Task<OpensignSignature> CreateOpensignSignature(string loginData)
        {
            logger.LogDebug("GenerateOpensignSignature");
            var abstractSignature = await _opensignSignatureFactory.GenerateOpensignSignature(loginData);
            logger.LogDebug("Done GenerateOpensignSignature");
            if (!(abstractSignature is OpensignSignature))
            {
                throw new ArgumentException("argument of type " + abstractSignature.GetType() + " is not valid output from the sign applet");
            }
            logger.LogDebug("VerifySignature");
            await VerifySignature(abstractSignature);
            logger.LogDebug("Done VerifySignature");
            return (OpensignSignature)abstractSignature;
        }

        private async Task VerifySignature(OpensignAbstractSignature signature)
        {
            logger.LogDebug("Verify");
            if (!await signature.Verify())
            {
                throw new ArgumentException("sign signature is not valid");
            }
            logger.LogDebug("Done Verify");
        }

        private Task<string> EncodeSignature(OpensignSignature opensignSignature)
        {
            return Base64Encode(opensignSignature.Signtext);
        }

        private async Task ValidateSignatureParameters(OpensignSignature opensignSignature, string challenge, string logonto)
        {
            logger.LogDebug("ValidateChallenge");
            await ValidateChallenge(opensignSignature, challenge);
            logger.LogDebug("Done ValidateChallenge");
            logger.LogDebug("ValidateVisibleToSignerForSignText");
            await ValidateVisibleToSignerForSignText(opensignSignature);
            logger.LogDebug("Done ValidateVisibleToSignerForSignText");
            if (logonto != null)
            {
                logger.LogDebug("ValidateLogonto");
                await ValidateLogonto(opensignSignature, logonto);
                logger.LogDebug("Done ValidateLogonto");
            }
        }

        private async Task ValidateChallenge(OpensignSignature opensignSignature, string challenge)
        {
            logger.LogDebug("VerifyChallenge");
            await _challengeVerifier.VerifyChallenge(opensignSignature, challenge);
            logger.LogDebug("Done VerifyChallenge");
        }

        private async Task ValidateVisibleToSignerForSignText(OpensignSignature signature)
        {
            SignatureProperty signtextProperty = signature.SignatureProperties["signtext"];
            logger.LogDebug("IsNotSignedXmlDocument");
            if (await IsNotSignedXmlDocument(signature) && !signtextProperty.VisibleToSigner)
            {
                throw new ServiceProviderException("Invalid sign signature - the parameter signtext in the signature " +
                    "must have the attribute visibleToSigner set to true");
            }
            logger.LogDebug("Done IsNotSignedXmlDocument");
        }

        private Task<bool> IsNotSignedXmlDocument(OpensignSignature opensignSignature)
        {
            return Task.FromResult(opensignSignature.StylesheetDigest == null);
        }

        private async Task ValidateLogonto(OpensignSignature signature, string logonto)
        {
            logger.LogDebug("GetSignatureProperty");
            SignatureProperty logontoProperty = await GetSignatureProperty(signature, "logonto");
            logger.LogDebug("Done GetSignatureProperty");
            logger.LogDebug("GetSignatureProperty");
            SignatureProperty requestIssuerProperty = await GetSignatureProperty(signature, "RequestIssuer");
            logger.LogDebug("Done GetSignatureProperty");
            if (logontoProperty != null && requestIssuerProperty != null)
            {
                throw new InvalidOperationException("Invalid signature logonto and RequestIssuer parameters cannot both be set");
            }

            if (logontoProperty == null && requestIssuerProperty == null)
            {
                throw new InvalidOperationException("Invalid signature either logonto or RequestIssuer parameters must be set");
            }

            if (logontoProperty != null)
            {
                String logontoPropertyValue = logontoProperty.Value;
                if (logontoPropertyValue != logonto)
                {
                    throw new ServiceProviderException("Invalid signature logonto parameter does not match expected value. Expected: "
                            + logonto + " actual: " + logontoPropertyValue);
                }
            }

            if (requestIssuerProperty != null)
            {
                String requestIssuerValue = requestIssuerProperty.Value;
                if (requestIssuerValue != logonto)
                {
                    throw new ServiceProviderException("Invalid signature RequestIssuer parameter does not match expected value. Expected: "
                            + logonto + " actual: " + requestIssuerValue);
                }
            }
        }

        private Task<SignatureProperty> GetSignatureProperty(OpensignSignature signature, string propertyKey)
        {
            try
            {
                return Task.FromResult(signature.SignatureProperties[propertyKey]);
            }
            catch (KeyNotFoundException)
            {
                return Task.FromResult<SignatureProperty>(null);
            }
        }
    }
}
