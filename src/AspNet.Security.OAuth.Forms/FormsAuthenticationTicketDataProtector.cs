using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security.DataProtection;
using System.Web.Security;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace AspNet.Security.OAuth.Forms
{
    class FormsAuthenticationTicketDataProtector : IDataProtector
    {
        public byte[] Protect(byte[] userData)
        {
            FormsAuthenticationTicket ticket;
            using (var memoryStream = new MemoryStream(userData))
            {
                var binaryFormatter = new BinaryFormatter();
                ticket = binaryFormatter.Deserialize(memoryStream) as FormsAuthenticationTicket;
            }

            if (ticket == null)
            {
                return null;
            }

            try
            {
                var encryptedTicket = FormsAuthentication.Encrypt(ticket);

                return encryptedTicket.ToBytesFromHexadecimal();
            }
            catch
            {
                return null;
            }
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            FormsAuthenticationTicket ticket;
            try
            {
                ticket = FormsAuthentication.Decrypt(protectedData.ToHexadecimal());
            }
            catch
            {
                return null;
            }

            if (ticket == null)
            {
                return null;
            }

            using (var memoryStream = new MemoryStream())
            {
                var binaryFormatter = new BinaryFormatter();

                binaryFormatter.Serialize(memoryStream, ticket);

                return memoryStream.ToArray();
            }
        }
    }
}
