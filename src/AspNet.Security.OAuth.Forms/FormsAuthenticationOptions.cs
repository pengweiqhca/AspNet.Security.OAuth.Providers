using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;

namespace AspNet.Security.OAuth.Forms
{
    public class FormsAuthenticationOptions
    {
        public FormsAuthenticationOptions()
        {
            CookieSecure = CookieSecureOption.SameAsRequest;
            ReturnUrlParameter = "ReturnUrl";
        }

        public ICookieManager CookieManager { get; set; }
        public CookieSecureOption CookieSecure { get; set; }
        public AuthenticationDescription Description { get; set; }
        public PathString LogoutPath { get; set; }
        public ICookieAuthenticationProvider Provider { get; set; }
        public string ReturnUrlParameter { get; set; }
        //public IAuthenticationSessionStore SessionStore { get; set; }
        public ISystemClock SystemClock { get; set; }
    }
}
