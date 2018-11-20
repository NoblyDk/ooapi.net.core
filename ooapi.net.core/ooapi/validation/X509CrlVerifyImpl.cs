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
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Org.BouncyCastle.Security.Certificates;

/**
 * This class is our own implementation of a method in the class X509Crl (full: Org.BouncyCastle.X509.X509Crl)
 * 
 * We made our own implementation of the method: Verify(AsymmetricKeyParameter publicKey).
 * 
 * The reason behind our own implementation is that that we experienced a perfomance issue with the Bouncy Castle
 * implementation of the method, the method taking between 1.5 - 2.5 seconds to finish.
 * 
 * The time consuming part in the Bouncy Castle implementation was converting the full CRL to bytes(in code): byte[] encoded = this.GetTbsCertList();
 * 
 * The byte conversion was made for each certificate wanting to validate. 
 * 
 * Inspired by Sun's implementation of the interface X509CRL, we decided that the bytes should be converted once,
 * and stored in the Crl.cs class, so other certificates that needs validation, does not have the need to converted
 * the bytes again, as it is stores as an instance variable in the Crl class, which is then cached in the CrlCache
 * 
 * The bytes are store in the instance variable _TbsCertList in the class Crl.cs
 * 
 * Sun's implementation class of the X509CRL interface is sun.security.x509.X509CRLImpl
 * 
 */
namespace org.openoces.ooapi.validation
{
    public class X509CrlVerifyImpl : IX509CrlVerifyImpl
    {

        public Task Verify(AsymmetricKeyParameter publicKey, X509Crl _crl, byte[] _TbsCertList)
        {
            ISigner sig = SignerUtilities.GetSigner(_crl.SigAlgName);

            sig.Init(false, publicKey);
            sig.BlockUpdate(_TbsCertList, 0, _TbsCertList.Length);

            if (!sig.VerifySignature(_crl.GetSignature()))
            {
                throw new SignatureException("CRL does not verify with supplied public key.");
            }
            return Task.CompletedTask;
        }
    }
}
