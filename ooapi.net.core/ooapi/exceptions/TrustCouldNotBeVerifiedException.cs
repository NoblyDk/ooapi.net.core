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
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.environment;

namespace org.openoces.ooapi.exceptions 
{
    public class TrustCouldNotBeVerifiedException : Exception
    {
        public OcesCertificate OcesCertificate { get; private set; }
        public IEnumerable<OcesEnvironment> TrustedEnvironments { get; private set; }

        public TrustCouldNotBeVerifiedException(OcesCertificate ocesCertificate, IEnumerable<OcesEnvironment> environments) : base("Could not verify trust")
        {
            OcesCertificate = ocesCertificate;
            TrustedEnvironments = environments;
        }

        public override string ToString()
        {
            var s = "The chain: ";
            const string d = "->";
            foreach (var cert in OcesCertificate.CertificateChain.GetAwaiter().GetResult())
            {
                s += d;
                s += cert.Subject;
            }
            s += " could not be verified in any of the current trusted environments: " + TrustedEnvironments;
            s += ". Exception caused by: " + InnerException;
            return s;
        }
    }
}
