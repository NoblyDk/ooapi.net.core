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
using System.Linq;
using System.Text;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.signatures;

namespace org.openoces.securitypackage
{
    /// <summary>
    /// Signature validation result.
    /// </summary>
    public class SignatureValidationStatus : ISignatureValidationStatus
    {
        /// <value>The signature.</value>
        public readonly OpensignSignature Signature;
        /// <value>Current status of the certificate.</value>
        public readonly CertificateStatus CertificateStatus;
        /// <value>Signature matches.</value>
        public readonly bool SignatureMatches;
        /// <value>The certificate used for signing.</value>
        OcesCertificate certificate;
        ///  <value>Token representing the userID to be stored. Optional.</value>
        public string RememberUserIdToken { get; private set; }

        public SignatureValidationStatus(OpensignSignature signature, CertificateStatus certificateStatus, bool signatureMatches)
        {
            Signature = signature;
            CertificateStatus = certificateStatus;
            SignatureMatches = signatureMatches;
        }

        public SignatureValidationStatus(OpensignSignature signature, CertificateStatus certificateStatus, bool signatureMatches, string rememberUserIdToken)
            : this(signature, certificateStatus, signatureMatches)
        {
            RememberUserIdToken = rememberUserIdToken;
        }

        public OcesCertificate Certificate
        {
            get
            {
                if (certificate == null)
                {
                    certificate = Signature.SigningCertificate;
                }
                return certificate;
            }
	    }
    }
}
