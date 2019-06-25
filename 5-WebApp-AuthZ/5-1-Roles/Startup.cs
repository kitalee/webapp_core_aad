using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.Client.TokenCacheProviders;
using System.IdentityModel.Tokens.Jwt;
using WebApp_OpenIDConnect_DotNet.Infrastructure;
using WebApp_OpenIDConnect_DotNet.Services;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddOptions();

            // This is required to be instantiated before the OpenIdConnectOptions starts getting configured.
            // By default, the claims mapping will map claim names in the old format to accommodate older SAML applications.
            // 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' instead of 'roles'
            // This flag ensures that the ClaimsIdentity claims collection will be built from the claims in the token
            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

            // Token acquisition service based on MSAL.NET
            // and chosen token cache implementation
            services.AddAzureAdV2Authentication(Configuration)
                                .AddMsal(new string[] { Constants.ScopeUserRead })
                                .AddInMemoryTokenCaches();

            // Add Graph
            services.AddGraphService(Configuration);
            services.AddAuthorization(option => option.AddPolicy("SubGroupOnly", policy => policy.RequireClaim("groups", "7b911a00-4cda-4ac8-8e9b-38255412c62c")));
            services.AddAuthorization(option => option.AddPolicy("SubGroup2-Part1Only", policy => policy.RequireClaim("groups", "9a269943-07ba-4a85-bc48-8706f495d154")));
            services.AddAuthorization(option => option.AddPolicy("DirectoryViewerRole", policy => policy.RequireClaim("roles", AppRoles.DirectoryViewers)));
            services.AddAuthorization(option => option.AddPolicy("UserReaderRole", policy => policy.RequireClaim("roles", AppRoles.UserReaders)));

            services.AddAuthorization(option => option.AddPolicy("BothRole", policy => {
                policy.RequireRole(AppRoles.DirectoryViewers, AppRoles.UserReaders);
                //policy.RequireClaim("roles", AppRoles.DirectoryViewers, AppRoles.UserReaders);
            }));

            services.AddAuthorization(option => option.AddPolicy("MixedRole", policy => {
                policy.RequireAssertion(ctx =>
                {
                    return ctx.User.HasClaim("groups", "7b911a00-4cda-4ac8-8e9b-38255412c62c") || ctx.User.IsInRole(AppRoles.DirectoryViewers);
                });
            }));

            services.Configure<OpenIdConnectOptions>(AzureADDefaults.OpenIdScheme, options =>
            {
                // The claim in the Jwt token where App roles are available.
                options.TokenValidationParameters.RoleClaimType = "roles";
            });

            services.AddMvc(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            })
            .SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}