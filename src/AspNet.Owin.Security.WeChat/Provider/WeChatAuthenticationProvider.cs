using System;
using System.Threading.Tasks;

namespace AspNet.Owin.Security.WeChat.Provider
{
    public class WeChatAuthenticationProvider : IWeChatAuthenticationProvider
    {
        public WeChatAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult(0);
            OnReturnEndpoint = context => Task.FromResult(0);
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        public Func<WeChatAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<WeChatReturnEndpointContext, Task> OnReturnEndpoint { get; set; }
        public Action<WeChatApplyRedirectContext> OnApplyRedirect { get; set; }

        public virtual Task Authenticated(WeChatAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(WeChatReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        public virtual void ApplyRedirect(WeChatApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}
