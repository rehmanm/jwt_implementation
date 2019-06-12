using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationService.Models
{
    public class JWTContainerModel : IAuthContainerModel
    {
        public int ExpireMinutes { get; set; } = Convert.ToInt32(System.Configuration.ConfigurationManager.AppSettings["JwtExpiry"].ToString() ?? "24 * 7 * 60");

        public string SecretKey { get; set; } = System.Configuration.ConfigurationManager.AppSettings["JwtModelKey"].ToString() ?? "TW9zaGVFcmV6UHJpdmF0ZUtleQ ==";
        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256Signature;
        public Claim[] Claims { get; set; }
    }
}
