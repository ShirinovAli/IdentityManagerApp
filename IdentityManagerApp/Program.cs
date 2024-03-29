using IdentityManagerApp;
using IdentityManagerApp.Data;
using IdentityManagerApp.Models;
using IdentityManagerApp.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(opt =>
{
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAccess");
});

builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Lockout.MaxFailedAccessAttempts = 3;
    opt.SignIn.RequireConfirmedEmail = false;
    opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
});

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    opt.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    opt.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("create", "True"));
    opt.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => policy
                    .RequireRole(SD.Admin)
                    .RequireClaim("create", "True")
                    .RequireClaim("edit", "True")
                    .RequireClaim("delete", "True"));
});

builder.Services.AddAuthentication().AddMicrosoftAccount(opt =>
{
    opt.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
    opt.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
});

builder.Services.AddAuthentication().AddFacebook(opt =>
{
    opt.ClientId = builder.Configuration["Authentication:Facebook:ClientId"];
    opt.ClientSecret = builder.Configuration["Authentication:Facebook:ClientSecret"];
});

builder.Services.AddAuthentication().AddGoogle(opt =>
{
    opt.ClientId = builder.Configuration["Authentication:Google:ClientId"];
    opt.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
