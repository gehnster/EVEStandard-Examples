﻿using EVEStandard.Enumerations;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;

namespace EVEStandard.ASPNETCoreSample
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
                // This is set to false to allow the SSOState cookie to be persisted in the user's session cookie as\
                // required by the auth security check. If you need to set this value to true you should refer to 
                // https://docs.microsoft.com/en-us/aspnet/core/security/gdpr for additiona guidance.
                options.CheckConsentNeeded = context => false;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            // Add cookie authentication and set the login url
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Auth/Login";
                });

            // Register your application at: https://developers.eveonline.com/applications to obtain client ID and secret key and add them to user secrets
            // by right-clicking the solution and selecting Manage User Secrets.
            // Also, modify the callback URL in appsettings.json to match with your environment.

            // Initialize the client
            var esiClient = new EVEStandardAPI(
                    "EVEStandard",                  // User agent
                    DataSource.Tranquility,         // Server [Tranquility/Singularity]
                    TimeSpan.FromSeconds(30));       // Timeout

            // Register with DI container
            services.AddSingleton<EVEStandardAPI>(esiClient);

            // Register EVEStandard SSO if you want to use it, you don't have to use EVEStandard SSO with EVEStandard.
            var sso = new SSOv2(DataSource.Tranquility, Configuration["SSOCallbackUrl"], Configuration["ClientId"], Configuration["SecretKey"]);
            services.AddSingleton<SSOv2>(sso);

            // Session is required 
            services.AddSession();

            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public static void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();
            app.UseSession();
            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
