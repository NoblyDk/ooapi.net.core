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
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace org.openoces.ooapi.certificate
{
    public class Ca
    {
        public X509Certificate2 Certificate { get; private set; }
        public Ca IssuingCa { get; private set; }

        /// <summary>
        /// Constructs a CA with <code>certificate</code> as the certificate of this
        /// CA and <code>issuingCa</code> as the parent CA which has signed the
        /// certificate of this CA
        /// </summary>
        /// <param name="certificate">CA certificate</param>
        /// <param name="issuingCa">CA which has signed the certificate of this CA</param>
        public Ca(X509Certificate2 certificate, Ca issuingCa)
        {
            if (certificate == null)
            {
                throw new ArgumentException("Certificate cannot be null");
            }
            Certificate = certificate;
            IssuingCa = issuingCa;
        }


        /// <summary>
        ///  Returns <code>true></code> if this CA is a root CA otherwise false
        /// </summary>
        public bool IsRoot
        {
            get
            {
                if (IssuingCa != null)
                {
                    return false;
                }
                try
                {
                    Certificate.Verify();
                    return true;
                }
                catch (CryptographicException)
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Gets the public key of this CA
        /// </summary>
        /// <returns>public key of this CA</returns>
        public byte[] PublicKey
        {
            get { return Certificate.GetPublicKey(); }
        }
    }
}
