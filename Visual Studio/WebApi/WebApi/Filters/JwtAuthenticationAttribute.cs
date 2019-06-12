using AuthenticationService.Managers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;

namespace WebApi.Filters
{
    public class JwtAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        public bool AllowMultiple => false;
        public string Realm { get; set; }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {

            var request = context.Request;

            var authorization = request.Headers.Authorization;

            if (authorization == null || authorization.Scheme != "Bearer" || string.IsNullOrEmpty(authorization.Parameter)) {
                context.ErrorResult = new AuthenticationFailureResult("JWT Token is Missing", request);
                return;
            }

            if (string.IsNullOrEmpty(authorization.Parameter)) {
                context.ErrorResult = new AuthenticationFailureResult("Invalid Token", request);
                return;

            }

            var token = authorization.Parameter;
             

            var principal = await AuthenticateJwtToken(token);

            if (principal == null)
            {
                context.ErrorResult = new AuthenticationFailureResult("Invalid JWT Token", request);
            }
            else
            {
                context.Principal = principal;
            }





        }

        private static bool ValidateToken(string token, out string username)
        {
            username = null;


            IAuthService authService = new JWTService(System.Configuration.ConfigurationManager.AppSettings["JwtModelKey"].ToString() ?? "TW9zaGVFcmV6UHJpdmF0ZUtleQ ==");

            if (!authService.IsTokenValid(token)) {
                username = null;
            }

            else
            {
                List<Claim> claims = authService.GetTokenClaims(token).ToList();
                 
                username = claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Name)).Value;

            }

            if (string.IsNullOrEmpty(username))
                return false;
                        
            return true;
        }

        protected Task<IPrincipal> AuthenticateJwtToken(string token)
        {

            //if (!authService.IsTokenValid(token))
            //    context.ErrorResult = new AuthenticationFailureResult("Invalid token", request);
            //else
            //{
            //    List<Claim> claims = authService.GetTokenClaims(token).ToList();

            //    Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Name)).Value);
            //    Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Email)).Value);
            //}

            string username;

            if (ValidateToken(token, out username))
            {
                // based on username to get more information from database in order to build local identity
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username)
                };

                var identity = new ClaimsIdentity(claims, "Jwt");
                IPrincipal user = new ClaimsPrincipal(identity);

                return Task.FromResult(user);
            }

            return Task.FromResult<IPrincipal>(null);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
                            
            Challenge(context);
            return Task.FromResult(0);
        }
        private void Challenge(HttpAuthenticationChallengeContext context)
        {
            string parameter = null;

            if (!string.IsNullOrEmpty(Realm))
                parameter = "realm=\"" + Realm + "\"";

            context.ChallengeWith("Bearer", parameter);
        }
    }
}   