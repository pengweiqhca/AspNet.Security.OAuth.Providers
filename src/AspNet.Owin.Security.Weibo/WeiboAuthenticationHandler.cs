﻿using AspNet.Owin.Security.Weibo.Provider;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AspNet.Owin.Security.Weibo
{
    public class WeiboAuthenticationHandler : AuthenticationHandler<WeiboAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        public WeiboAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues(nameof(code));

                if (values != null && values.Count == 1)
                    code = values[0];

                values = query.GetValues(nameof(state));
                if (values != null && values.Count == 1)
                    state = values[0];

                properties = Options.StateDataFormat.Unprotect(state);

                if (properties == null)
                    return null;

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                    return new AuthenticationTicket(null, properties);

                if (string.IsNullOrEmpty(code))
                    return new AuthenticationTicket(null, properties);


                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                var tokenEndpoint = Options.TokenEndpoint +
                                      "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                                      "&client_secret=" + Uri.EscapeDataString(Options.ClientSecret) +
                                      "&grant_type=code" +
                                      "&code=" + Uri.EscapeDataString(code) +
                                      "&redirect_uri=" + Uri.EscapeDataString(redirectUri);

                var tokenResponse = await _httpClient.GetAsync(tokenEndpoint, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();

                var token = JObject.Parse(await tokenResponse.Content.ReadAsStringAsync());

                var accessToken = token.Value<string>("access_token");
                var expiresIn = token.Value<string>("expires_in");

                if (string.IsNullOrEmpty(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                var userInformationEndpoint = Options.UserInformationEndpoint +
                                                 "?access_token=" + Uri.EscapeDataString(accessToken);

                var response = await _httpClient.GetAsync(userInformationEndpoint, Request.CallCancelled);
                response.EnsureSuccessStatusCode();

                var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                var context = new WeiboAuthenticatedContext(Context, user, accessToken, expiresIn);

                context.Identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString,
                        Options.AuthenticationType),
                    new Claim(ClaimTypes.Name, context.Name, XmlSchemaString,
                        Options.AuthenticationType),
                    new Claim("urn:weiboaccount:id", context.Id, XmlSchemaString,
                        Options.AuthenticationType),
                    new Claim("urn:weiboaccount:name", context.Name, XmlSchemaString,
                        Options.AuthenticationType),
                    new Claim(ClaimTypes.Gender, context.Gender, XmlSchemaString, Options.AuthenticationType)
                },
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }

        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Request.Path == Options.CallbackPath)
            {
                var ticket = await AuthenticateAsync();

                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new WeiboReturnEndpointContext(Context, ticket)
                {
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                    RedirectUri = ticket.Properties.RedirectUri
                };

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
                {
                    var identity = context.Identity;
                    if (!string.Equals(identity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        identity = new ClaimsIdentity(identity.Claims, context.SignInAsAuthenticationType, identity.NameClaimType, identity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, identity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    var redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }
                return context.IsRequestCompleted;

            }
            return false;
        }
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult(0);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                var basrUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
                var currentUri = basrUri + Request.Path + Request.QueryString;
                var redirectUri = basrUri + Options.CallbackPath;

                var properties = challenge.Properties;

                if (string.IsNullOrEmpty(properties.RedirectUri))
                    properties.RedirectUri = currentUri;

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                var state = Options.StateDataFormat.Protect(properties);

                var authorizationEndpoint = Options.AuthorizationEndpoint +
                                               "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                                               "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                                               "&state=" + Uri.EscapeDataString(state);

                var context = new WeiboApplyRedirectContext(Context, Options, authorizationEndpoint, properties);

                Options.Provider.ApplyRedirect(context);
            }
            return Task.FromResult(0);
        }



    }
}
