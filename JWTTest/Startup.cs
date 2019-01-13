using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using JWTTest.Data;
using JWTTest.Services;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using JWTTest.Middleware;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace JWTTest
{
    public class Startup
    {
        private static readonly string secretKey = "my_super_secret_key";
        private static readonly string issuer = "www.sample.com.tw";
        private static readonly string audience = "www.etmall.com.tw";
        private static SymmetricSecurityKey signingKey;

        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>(o=>
            {
                o.Password.RequireDigit = false;
                o.Password.RequiredLength = 0;
                o.Password.RequireLowercase = false;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequireUppercase = false;

            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            services.AddMvc()
                .AddRazorPagesOptions(options =>
                {
                    options.Conventions.AuthorizeFolder("/Account/Manage");
                    options.Conventions.AuthorizePage("/Account/Logout");
                });

            services.AddOptions();
            services.Configure<TokenValidationParameters>(options =>
            {
                options.ValidateIssuerSigningKey = true;
                options.IssuerSigningKey = signingKey;
                options.ValidateIssuer = true;
                options.ValidIssuer = issuer;
                options.ValidateAudience = true;
                options.ValidAudience = audience;
            });

            //³]¸mJWT Cookie!?
            //var tokenValidationParameters = new TokenValidationParameters
            //{
            //    //The signing key must match !
            //    ValidateIssuerSigningKey = true,
            //    IssuerSigningKey = signingKey,

            //    //Validate the JWT Issuer (iss) claim
            //    ValidateIssuer = true,
            //    ValidIssuer = issure,

            //    //validate the JWT Audience (aud) claim

            //    ValidateAudience = true,
            //    ValidAudience = audience,

            //    //validate the token expiry
            //    ValidateLifetime = true,

            //    // If you  want to allow a certain amout of clock drift
            //    ClockSkew = TimeSpan.Zero
            //};

            //services.AddAuthentication(o =>
            //{
            //    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

            //}).AddJwtBearer(options =>
            //{
            //    options.TokenValidationParameters = tokenValidationParameters;

            //}).AddCookie(options =>
            //{
            //    options.ExpireTimeSpan = TimeSpan.FromDays(150);
            //    options.LoginPath = "/Account/Login";
            //    options.LogoutPath = "/Account/LogOff";
            //});

            // Register no-op EmailSender used by account confirmation and password reset during development
            // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=532713
            services.AddSingleton<IEmailSender, EmailSender>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            // Add JWT generation endpoint:
            var jwtOptions = new TokenProviderOptions
            {
                Audience = audience,
                Issuer = issuer,
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
            };
            app.UseJWTTokenProviderMiddleware(Options.Create(jwtOptions));

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}");
            });
        }
    }
}
