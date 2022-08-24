using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.IdentityModel.Tokens;
using NET6AWSCognitoWebApp.Helpers;

var builder = WebApplication.CreateBuilder(args);

// Add Azure KeyVault
//builder.Configuration.AddAzureKeyVault(new Uri($"https://{builder.Configuration.GetSection("KeyVaultName").Value.ToString()}.vault.azure.net/"), new DefaultAzureCredential());

builder.Services.AddControllersWithViews();

// https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-3.1#forwarded-headers-middleware-order
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedProto |
        ForwardedHeaders.XForwardedHost;
});

// https://docs.microsoft.com/en-us/aspnet/core/fundamentals/localization?view=aspnetcore-3.1
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");

builder.Services.AddHttpContextAccessor();

builder.Services.AddMvc()
    .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
    .AddDataAnnotationsLocalization();

// Remove CS8600 Warning for possible non-nullable types
builder.Services.AddControllers(options => options.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes = true);

// Add services to the container.
builder.Services.AddRazorPages();

// Define HTTPClient for use and DI
// https://docs.microsoft.com/en-us/dotnet/architecture/microservices/implement-resilient-applications/use-httpclientfactory-to-implement-resilient-http-requests
builder.Services.AddHttpClient();


#region Helpers
builder.Services.AddScoped<IUserHelper, UserHelper>();

// Initialize the Http Helper
//builder.Services.AddSingleton<HttpClientHelper>();

// For RazorViewRenderHelper
//builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
#endregion

#region Amazon Cognito Authentication
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => {

        options.ClientId = builder.Configuration["Authentication:Cognito:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Cognito:ClientSecret"];
        options.Authority = $"{builder.Configuration.GetSection("Authentication:Cognito:Authority").Value}/{builder.Configuration.GetSection("Authentication:Cognito:PoolId").Value}";
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("phone");
        options.Scope.Add("aws.cognito.signin.user.admin");
        options.ResponseType = builder.Configuration["Authentication:Cognito:ResponseType"];
        options.MetadataAddress = builder.Configuration["Authentication:Cognito:MetadataAddress"];

        options.SaveTokens = true;

        options.TokenValidationParameters = new TokenValidationParameters()
        {
            NameClaimType = builder.Configuration.GetSection("Authentication:UserNameClaim").Value
        };

        options.Events = new OpenIdConnectEvents()
        {
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                var logoutUri = $"{builder.Configuration.GetSection("Authentication:Cognito:LogoutUri").Value}/logout?client_id={builder.Configuration.GetSection("Authentication:Cognito:ClientId").Value}";

                logoutUri += $"&logout_uri={context.Request.Scheme}://{context.Request.Host}";

                // delete cookies
                context.Properties.Items.Remove(CookieAuthenticationDefaults.AuthenticationScheme);
                // close openid session
                context.Properties.Items.Remove(OpenIdConnectDefaults.AuthenticationScheme);

                context.Response.Redirect(logoutUri);
                context.HandleResponse();

                return Task.CompletedTask;
            }
        };
    });

// add Authorization for Cognito user roles
builder.Services.AddAuthorization(options => {
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "cognito:groups" && c.Value == "Admin")));
});
#endregion



var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

// https://docs.microsoft.com/en-us/aspnet/core/fundamentals/localization?view=aspnetcore-6.0
var supportedCultures = new[] { "en-US" };
var localizationOptions = new RequestLocalizationOptions().SetDefaultCulture(supportedCultures[0])
    .AddSupportedCultures(supportedCultures)
    .AddSupportedUICultures(supportedCultures);
app.UseRequestLocalization(localizationOptions);

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
   endpoints.MapControllerRoute(
       name: "default",
       pattern: "{controller=Home}/{action=Index}/{id?}");
});
//app.MapRazorPages();

app.Run();
