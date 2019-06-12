using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using AuthenticationService.Managers;
using AuthenticationService.Models;
namespace WebApi.Controllers
{
    public class TokenController : ApiController
    {


        [AllowAnonymous]
        public string Get(string name, string email)
        { 
            IAuthContainerModel model = new JWTContainerModel()
            {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, name),
                    new Claim(ClaimTypes.Email, email)
                }
            }; 
            IAuthService authService = new JWTService(model.SecretKey);
             
            string token = authService.GenerateToken(model);

            return token;
        }
    }
}