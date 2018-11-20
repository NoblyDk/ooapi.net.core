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
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.certificate
{
    public class PocesCertificate : OcesCertificate
    {
        /// <summary>
        /// Contructs a POCES certificate with the given <code>CA</code> as parent  
        /// </summary>
        /// <param name="certificate">certificate</param>
        /// <param name="parent">parent signing CA</param>
        public PocesCertificate(X509Certificate2 certificate, Ca parent)
            : base(certificate, parent)
        {
        }

        /// <summary>
        /// </summary>
        /// <returns><code>true</code> if this certificate has the string "Pseudonym" as name</returns>
        public bool HasPseudonym()
        {
            return new X509CertificatePropertyExtrator().HasPseudonym(Certificate).GetAwaiter().GetResult();
        }

        /// <summary>
        /// </summary>
        /// <returns><code>true</code> if this certificate is a youth certificate</returns>
        public bool IsYouthCertificate()
        {
            var element = new X509CertificatePropertyExtrator().GetElementInX509Name(Certificate, ObjectIdentifiers.OrganizationalUnit).GetAwaiter().GetResult();
            return element != null &&
                element == "Ung mellem 15 og 18 - Kan som udgangspunkt ikke lave juridisk bindende aftaler";
        }

        /// <summary>
        ///  Gets the PID of the personal certificate
        /// </summary>
        public string Pid
        {
            get
            {
                return SubjectSerialNumber.Substring("PID:".Length);
            }
        }
    }
}
