using JWTTest.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JWTTest.Middleware
{
    public class TokenProviderMiddleware
    {
        private readonly RequestDelegate _next;
        private TokenProviderOptions _options;
        private UserManager<ApplicationUser> _userManager;
        private ApplicationDbContext _db;
        private TokenValidationParameters _validationParameters;

        public TokenProviderMiddleware(
            RequestDelegate next,
            IOptions<TokenProviderOptions> options,
            IOptions<TokenValidationParameters> validationParameters
            )
        {
            _next = next;
            _options = options.Value;
            _validationParameters = validationParameters.Value;
        }

        public Task Invoke(HttpContext context, UserManager<ApplicationUser> userManager, ApplicationDbContext db)
        {
            _db = db;

            _userManager = userManager;

            // If the request path doesn't match, skip
            if (!context.Request.Path.Equals(_options.Path, StringComparison.Ordinal))
            {
                #region  驗證token是否正確
                string accessToken = context.Request.Headers["Authorization"].FirstOrDefault() ?? string.Empty;
                string bearer = "Bearer ";

                if (accessToken.StartsWith(bearer, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        accessToken = accessToken.Substring(bearer.Length);
                        var validation = new JwtSecurityTokenHandler().ValidateToken(accessToken, _validationParameters, out SecurityToken securityToken);
                    }
                    catch (Exception)
                    {
                        //token fail exception
                        return context.Response.WriteAsync("Invalid Token To Access");
                    }
                    
                }
                #endregion  驗證token是否正確

                return _next(context);
            }

            // Request must be POST with Content-Type: application/x-www-form-urlencoded
            if (!context.Request.Method.Equals("POST") || !context.Request.HasFormContentType)
            {
                context.Response.StatusCode = 400;
                return context.Response.WriteAsync("Bad Request");
            }

            return GenerateToken(context);
        }

        private async Task GenerateToken(HttpContext context)
        {
            string username = context.Request.Form["username"];
            string password = context.Request.Form["password"];

            ApplicationUser user = null;
            user = _db.Users.Where(x => x.UserName == username).FirstOrDefault();

            var result = _userManager.CheckPasswordAsync(user, password);
            if (result.Result == false)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid username or password");
                return;
            }
            var now = DateTime.UtcNow;


            var userClaims = await _userManager.GetRolesAsync(user);

            // Specifically add the jti (random nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            foreach (var role in userClaims)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Create the JWT and write it to a string
            var jwt = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(_options.Expiration),
                signingCredentials: _options.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                accessToken = encodedJwt,
                expireSeconds = (int)_options.Expiration.TotalSeconds
            };

            //var validationParameters = new TokenValidationParameters()
            //{
            //    RequireExpirationTime = true,
            //    ValidateIssuer = false,
            //    ValidateAudience = false,
            //    IssuerSigningKey = new SymmetricSecurityKey(symmetricKey)
            //};
            //var validation = new JwtSecurityTokenHandler().ValidateToken();

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, new JsonSerializerSettings { Formatting = Formatting.Indented }));
        }

    }
    public static class TokenProviderMiddlewareExtensions
    {
        public static IApplicationBuilder UseJWTTokenProviderMiddleware(this IApplicationBuilder builder, IOptions<TokenProviderOptions> options)
        {
            return builder.UseMiddleware<TokenProviderMiddleware>(options);
        }
    }
}
