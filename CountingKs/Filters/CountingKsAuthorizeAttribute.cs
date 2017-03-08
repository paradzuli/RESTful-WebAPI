using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using CountingKs.Data;
using Ninject;
using WebMatrix.WebData;

namespace CountingKs.Filters
{
    public class CountingKsAuthorizeAttribute: AuthorizationFilterAttribute
    {
        private bool _perUser;

        public CountingKsAuthorizeAttribute(bool perUser=true)
        {
            _perUser = perUser;
        }

        [Inject]
        public CountingKsRepository TheRepository { get; set; }

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            const string APIKEYNAME = "apiKey";
            const string TOKENNAME = "token";

            var query = HttpUtility.ParseQueryString(actionContext.Request.RequestUri.Query);

            if (!string.IsNullOrWhiteSpace(query[APIKEYNAME]) && !string.IsNullOrWhiteSpace(query[TOKENNAME]))
            {
                var apikey = query[APIKEYNAME];
                var token = query[TOKENNAME];

                var authToken = TheRepository.GetAuthToken(token);

                if (authToken != null && authToken.ApiUser.AppId == apikey && authToken.Expiration > DateTime.UtcNow)
                {



                    if (_perUser)
                    {
                        if (Thread.CurrentPrincipal.Identity.IsAuthenticated)
                        {
                            return;
                        }
                        var authorizationHeader = actionContext.Request.Headers.Authorization;

                        if (authorizationHeader != null)
                        {
                            if (authorizationHeader.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase) &&
                                !String.IsNullOrWhiteSpace(authorizationHeader.Parameter))
                            {
                                var rawCredentials = authorizationHeader.Parameter;
                                var encoding = Encoding.GetEncoding("iso-8859-1");
                                var credentials = encoding.GetString(Convert.FromBase64String(rawCredentials));
                                var split = credentials.Split(':');
                                var username = split[0];
                                var password = split[1];

                                if (!WebSecurity.Initialized)
                                {
                                    WebSecurity.InitializeDatabaseConnection("DefaultConnection", "UserProfile",
                                        "UserId",
                                        "UserName", autoCreateTables: true);
                                }
                                if (WebSecurity.Login(username, password))
                                {
                                    var principal = new GenericPrincipal(new GenericIdentity(username), null);
                                    Thread.CurrentPrincipal = principal;
                                    return;
                                }
                            }
                        }


                    }
                    else
                    {
                        return;
                    }
                }
            }
            HandleUnauthorized(actionContext);
        }

        private void HandleUnauthorized(HttpActionContext actionContext)
        {
            actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            actionContext.Response.Headers.Add("WWW-Authenticate","Basic Scheme='CountingKs' location='http://localhost:8901/account/login'");
        }
    }
}