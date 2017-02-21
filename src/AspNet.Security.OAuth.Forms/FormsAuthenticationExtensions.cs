using AspNet.Security.OAuth.Forms;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataHandler;
using System;
using System.Web.Security;

namespace Owin
{
    // asp.net core解密 forms authentication cookie
    // http://www.hanselman.com/blog/SharingAuthorizationCookiesBetweenASPNET4xAndASPNETCore10.aspx
    // https://www.cnblogs.com/xishuai/p/aspnet-5-or-core1--identity-part-two.html
    // http://www.dailytech5.com/news_show.aspx?id=192198
    public static class FormsAuthenticationExtensions
    {
        public static IAppBuilder UseFormAuthentication(this IAppBuilder app)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            return app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                CookieName = FormsAuthentication.FormsCookieName,
                CookieDomain = FormsAuthentication.CookieDomain,
                CookiePath = FormsAuthentication.FormsCookiePath,
                CookieSecure = CookieSecureOption.SameAsRequest,
                LoginPath = new PathString(FormsAuthentication.LoginUrl),
                AuthenticationMode = AuthenticationMode.Active,
                ExpireTimeSpan = FormsAuthentication.Timeout,
                SlidingExpiration = FormsAuthentication.SlidingExpiration,
                AuthenticationType = "Forms",
                TicketDataFormat = new SecureDataFormat<AuthenticationTicket>(
                    new FormsAuthenticationTicketSerializer("Forms"),
                    new FormsAuthenticationTicketDataProtector(),
                    new HexEncoder())
            });
        }
    }
}
