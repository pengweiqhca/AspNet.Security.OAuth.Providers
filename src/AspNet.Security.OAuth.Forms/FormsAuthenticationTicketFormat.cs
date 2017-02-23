using Microsoft.Owin.Security;
using System;
using System.Globalization;
using System.Security.Claims;
using System.Web.Security;
using Microsoft.Owin.Security.Cookies;

namespace AspNet.Security.OAuth.Forms
{
    class FormsAuthenticationTicketFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly CookieAuthenticationOptions _options;

        public FormsAuthenticationTicketFormat(CookieAuthenticationOptions options)
        {
            _options = options;
        }

        public string Protect(AuthenticationTicket data)
        {
            var version = data.Identity.FindFirst(ClaimTypes.Version)?.Value;
            var ticket = new FormsAuthenticationTicket(
                version == null ? 2 : Convert.ToInt32(version),
                data.Identity.FindFirst(ClaimTypes.Name).Value,
                (data.Properties.IssuedUtc ?? _options.SystemClock.UtcNow).DateTime,
                (data.Properties.ExpiresUtc ?? _options.SystemClock.UtcNow.Add(_options.ExpireTimeSpan)).DateTime,
                data.Properties.IsPersistent,
                data.Identity.FindFirst(ClaimTypes.UserData)?.Value,
                data.Identity.FindFirst(ClaimTypes.CookiePath)?.Value ?? _options.CookiePath);

            return FormsAuthentication.Encrypt(ticket);
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            var ticket = FormsAuthentication.Decrypt(protectedText);
            if (ticket == null)
                return null;

            var identity = new ClaimsIdentity(_options.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Name, ticket.Name));
            identity.AddClaim(new Claim(ClaimTypes.IsPersistent, ticket.IsPersistent.ToString(), ClaimValueTypes.Boolean));
            identity.AddClaim(new Claim(ClaimTypes.Expired, ticket.Expired.ToString(), ClaimValueTypes.Boolean));
            identity.AddClaim(new Claim(ClaimTypes.Expiration, ticket.Expiration.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.DateTime));
            identity.AddClaim(new Claim(ClaimTypes.CookiePath, ticket.CookiePath));
            identity.AddClaim(new Claim(ClaimTypes.Version, ticket.Version.ToString(), ClaimValueTypes.Integer32));
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
