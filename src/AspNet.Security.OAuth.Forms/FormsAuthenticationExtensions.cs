using AspNet.Security.OAuth.Forms;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
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
        public static IAppBuilder UseFormsAuthentication(this IAppBuilder app) => UseFormsAuthentication(app, null);

        public static IAppBuilder UseFormsAuthentication(this IAppBuilder app, FormsAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            var cookieOptions = new CookieAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = FormsAuthenticationConstants.AuthenticationType,
                CookieDomain = FormsAuthentication.CookieDomain,
                CookieHttpOnly = true,
                CookieName = FormsAuthentication.FormsCookieName,
                CookiePath = FormsAuthentication.FormsCookiePath,
                CookieSecure = CookieSecureOption.SameAsRequest,
                ExpireTimeSpan = FormsAuthentication.Timeout,
                LoginPath = new PathString(FormsAuthentication.LoginUrl),
                ReturnUrlParameter = "ReturnUrl",
                SlidingExpiration = FormsAuthentication.SlidingExpiration
            };
            cookieOptions.TicketDataFormat = new FormsAuthenticationTicketFormat(cookieOptions);

            if (options != null)
            {
                cookieOptions.CookieManager = options.CookieManager;
                cookieOptions.CookieSecure = options.CookieSecure;
                cookieOptions.Description = options.Description;
                cookieOptions.LogoutPath = options.LogoutPath;
                cookieOptions.Provider = options.Provider;
                cookieOptions.ReturnUrlParameter = options.ReturnUrlParameter;
                //cookieOptions.SessionStore = options.SessionStore;
                cookieOptions.SystemClock = options.SystemClock;
            }

            return app.UseCookieAuthentication(cookieOptions);
        }
    }
}
