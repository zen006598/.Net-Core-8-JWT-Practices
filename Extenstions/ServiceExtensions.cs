using System.Text;
using IdentityJWTDemo.Configurations;
using IdentityJWTDemo.Data;
using IdentityJWTDemo.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace IdentityJWTDemo.Extensions;

public static class ServiceExtensions
{
  public static IServiceCollection AddDbContextServices(this IServiceCollection services, IConfiguration configuration)
  {
    var conStrBuilder = new SqlConnectionStringBuilder(configuration.GetConnectionString("MsSql"))
    {
      Password = configuration["MssqlConnection:Password"]
    };

    services.AddDbContext<ApplicationDbContext>(options =>
      options.UseSqlServer(conStrBuilder.ConnectionString));

    return services;
  }

  public static IServiceCollection AddApplicationServices(this IServiceCollection services)
  {
    services.AddScoped<ITokenService, TokenService>();
    return services;
  }

  public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
  {
    var jwtSettings = configuration.GetSection("JwtSettings").Get<JWTSetting>();
    services.AddSingleton(jwtSettings);

    services.AddIdentity<IdentityUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

    var tokenValidationParameters = new TokenValidationParameters
    {
      ValidateIssuerSigningKey = true,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret)),
      ValidateIssuer = true,
      ValidIssuer = jwtSettings.ValidIssuer,
      ValidateAudience = true,
      ValidAudience = jwtSettings.ValidAudience,
      ValidateLifetime = true,
      ClockSkew = TimeSpan.Zero
    };
    services.AddSingleton(tokenValidationParameters);

    services.AddAuthentication(options =>
    {
      options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
      options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
      options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
      options.SaveToken = true;
      options.RequireHttpsMetadata = false;
      options.TokenValidationParameters = tokenValidationParameters;
    });
    return services;
  }

  public static IServiceCollection AddSwaggerServices(this IServiceCollection services)
  {
    services.AddSwaggerGen(c =>
    {
      c.SwaggerDoc("v1", new OpenApiInfo { Title = "IdentityJWTDemo", Version = "v1" });
      c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
      {
        In = ParameterLocation.Header,
        Description = "Please enter JWT with Bearer into field",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
      });
      c.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
          {
              new OpenApiSecurityScheme
              {
                  Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer"}
              },
              new string[] {}
          }
        });
    });

    return services;
  }
}
