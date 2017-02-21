using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Serializer;
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Web.Security;

namespace AspNet.Security.OAuth.Forms
{
    class FormsAuthenticationTicketSerializer : IDataSerializer<AuthenticationTicket>
    {
        private readonly string _authenticationType;

        public FormsAuthenticationTicketSerializer(string authenticationType)
        {
            _authenticationType = authenticationType;
        }

        public byte[] Serialize(AuthenticationTicket model)
        {
            var userTicket = new FormsAuthenticationTicket(
                Convert.ToInt32(model.Identity.FindFirst(ClaimTypes.Version).Value),
                model.Identity.FindFirst(ClaimTypes.Name).Value,
                model.Properties.IssuedUtc.Value.UtcDateTime,
                model.Properties.ExpiresUtc.Value.UtcDateTime,
                model.Properties.IsPersistent,
                model.Identity.FindFirst(ClaimTypes.UserData).Value,
                model.Identity.FindFirst(ClaimTypes.CookiePath).Value);

            using (var dataStream = new MemoryStream())
            {
                var binaryFormatter = new BinaryFormatter();
                binaryFormatter.Serialize(dataStream, userTicket);

                return dataStream.ToArray();
            }
        }

        public AuthenticationTicket Deserialize(byte[] data)
        {
            using (var dataStream = new MemoryStream(data))
            {
                var binaryFormatter = new BinaryFormatter();
                var ticket = binaryFormatter.Deserialize(dataStream) as FormsAuthenticationTicket;
                if (ticket == null)
                    return null;

                var identity = new ClaimsIdentity(_authenticationType);
                identity.AddClaim(new Claim(ClaimTypes.Name, ticket.Name));
                identity.AddClaim(new Claim(ClaimTypes.IsPersistent, ticket.IsPersistent.ToString()));
                identity.AddClaim(new Claim(ClaimTypes.Expired, ticket.Expired.ToString()));
                identity.AddClaim(new Claim(ClaimTypes.Expiration, ticket.Expiration.ToString()));
                identity.AddClaim(new Claim(ClaimTypes.CookiePath, ticket.CookiePath));
                identity.AddClaim(new Claim(ClaimTypes.Version, ticket.Version.ToString()));
                identity.AddClaim(new Claim(ClaimTypes.UserData, ticket.UserData));

                return new AuthenticationTicket(identity, new AuthenticationProperties
                {
                    IssuedUtc = new DateTimeOffset(ticket.IssueDate),
                    ExpiresUtc = new DateTimeOffset(ticket.Expiration),
                    IsPersistent = ticket.IsPersistent
                });
            }
        }
    }
}
