using System;
using System.Text;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.signatures
{
    public class SignedDocument
    {
        public SignedDocument(byte[] signedContent, String mimeType)
        {
            this.SignedContent = signedContent;
            this.MimeType = mimeType;
        }
        public byte[] SignedContent { get; protected set; }
        public String MimeType { get; protected set; }

        public String GetSignedContentAsString()
        {
            if (!"text/plain".Equals(this.MimeType))
            {
                throw new InternalException("Only documents with mimetype text/plain may be retrieved as String", null);
            }
            return UTF8Encoding.UTF8.GetString(this.SignedContent);
        }
    }
}
