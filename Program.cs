using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using TodoAPI.Config;
using TodoAPI.Data;
using TodoAPI.Services;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<ApiDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default"))
);

//JWT Config
builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));

// Validation params
byte[]? key = Encoding.ASCII.GetBytes(builder.Configuration["JwtConfig:Secret"]);
TokenValidationParameters? tokenValidationParams = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false,
    ValidateAudience = false,
    ValidateLifetime = true,
    RequireExpirationTime = false
};

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(jwt =>
{

    jwt.SaveToken = true;
    jwt.TokenValidationParameters = tokenValidationParams;
});

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("TypePolicy",
                    policy => policy.RequireClaim("Type"));
});

builder.Services.AddSingleton(tokenValidationParams);

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options => { options.SignIn.RequireConfirmedAccount = true; })
    .AddEntityFrameworkStores<ApiDbContext>();

builder.Services.AddScoped<IJwtService, JwtService>();

var app = builder.Build();

SeedUserService.SeedDatabaseAsync(app.Services).Wait();



// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// app.UseHttpsRedirection();

app.UseAuthorization();

app.UseAuthentication();

app.MapControllers();

app.Run();
