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

namespace org.openoces.ooapi.certificate
{
    public class FocesCertificate : OcesCertificate
    {
        /// <summary>
        /// Contructs a FOCES certificate with the given <code>CA</code> as parent
        /// </summary>
        /// <param name="certificate">certificate</param>
        /// <param name="parent">parent signing CA</param>
        public FocesCertificate(X509Certificate2 certificate, Ca parent)
            : base(certificate, parent)
        {
        }

        /// <summary>
        /// Gets the FID of the functional certificate 
        /// </summary>
        /// <returns>The FID of the functional certificate</returns>
        public String Fid
        {
            get
            {
                return SubjectSerialNumber.Substring(LengthOfCvrXxxxxxxx + "-FID:".Length);
            }
        }

        /// <summary>
        /// Gets the CVR of the functional certificate 
        /// </summary>
        public string Cvr
        {
            get
            {
                return SubjectSerialNumber.Substring(LengthOfCvr, LengthOfCvrNumber);
            }
        }
    }
}
