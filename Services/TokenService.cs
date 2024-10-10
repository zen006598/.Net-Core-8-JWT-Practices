using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityJWTDemo.Configurations;
using IdentityJWTDemo.Data;
using IdentityJWTDemo.Models;
using IdentityJWTDemo.Parameters;
using IdentityJWTDemo.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityJWTDemo.Services;
public interface ITokenService
{
  Task<AuthViewModel> CreateTokenAsync(IdentityUser user);
  Task<AuthViewModel> VerifyAndGenerateToken(TokenParameter parameter);
  Task<RefreshToken> CreateRefreshToken(string jwtId, string userId);
  Task<bool> ValidateRefreshToken(string refreshToken, string jwtId);
}
public class TokenService(
    UserManager<IdentityUser> userManager,
    JWTSetting jwtSettings,
    TokenValidationParameters tokenValidationParameters,
    ApplicationDbContext dbContext,
    ILogger<TokenService> logger
) : ITokenService
{
  private readonly UserManager<IdentityUser> _userManager = userManager;
  private readonly JWTSetting _jwtSettings = jwtSettings;
  private readonly TokenValidationParameters _tokenValidationParameters = tokenValidationParameters;
  private readonly ApplicationDbContext _dbContext = dbContext;
  private readonly ILogger<TokenService> _logger = logger;

  public async Task<AuthViewModel> CreateTokenAsync(IdentityUser user)
  {
    var jwtToken = await CreateJwtToken(user);
    var refreshToken = await CreateRefreshToken(jwtToken.Id, user.Id);

    return new AuthViewModel
    {
      Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
      RefreshToken = refreshToken.Token,
      Success = true
    };
  }

  public async Task<AuthViewModel> VerifyAndGenerateToken(TokenParameter parameter)
  {
    var jwtTokenHandler = new JwtSecurityTokenHandler();

    try
    {
      // Validate JWT token format(JWS/JWE)
      var tokenInVerification = jwtTokenHandler.ValidateToken(parameter.Token, _tokenValidationParameters, out var validatedToken);

      // Validate encryption algorithm
      if (validatedToken is JwtSecurityToken jwtSecurityToken)
      {
        var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
        if (!result) return null;
      }

      // Validate expiry date
      // get the expire time from claim, which is in Unix time format
      var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
      var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);
      if (expiryDate > DateTime.UtcNow)
      {
        return new AuthViewModel
        {
          Success = false,
          Errors = new List<string> { "Token has not yet expired" }
        };
      }

      // Validate refresh token
      var storedRefreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == parameter.RefreshToken);
      if (storedRefreshToken == null)
      {
        return new AuthViewModel
        {
          Success = false,
          Errors = new List<string> { "Refresh Token does not exist" }
        };
      }

      // Check if refresh token has expired
      if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
      {
        return new AuthViewModel
        {
          Success = false,
          Errors = new List<string> { "Refresh Token has expired, user needs to re-login" }
        };
      }

      // Check if refresh token has been used
      if (storedRefreshToken.IsUsed)
      {
        return new AuthViewModel
        {
          Success = false,
          Errors = new List<string> { "Refresh Token has been used" }
        };
      }

      // Check if refresh token has been revoked
      if (storedRefreshToken.IsRevoked)
      {
        return new AuthViewModel
        {
          Success = false,
          Errors = new List<string> { "Refresh Token has been revoked" }
        };
      }

      // Validate JWT token Id
      var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
      if (storedRefreshToken.JwtId != jti)
      {
        return new AuthViewModel
        {
          Success = false,
          Errors = new List<string> { "The token doesn't match the saved token" }
        };
      }

      // Update current token to be used
      storedRefreshToken.IsUsed = true;
      _dbContext.RefreshTokens.Update(storedRefreshToken);
      await _dbContext.SaveChangesAsync();

      // Generate new tokens
      var user = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
      return await CreateTokenAsync(user);
    }
    catch (Exception ex)
    {
      _logger.LogError($"Error occurred while verifying the token {ex}");
      return new AuthViewModel
      {
        Success = false,
        Errors = new List<string> { "Token validation failed" }
      };
    }
  }

  public async Task<RefreshToken> CreateRefreshToken(string jwtId, string userId)
  {
    var refreshToken = new RefreshToken
    {
      JwtId = jwtId,
      IsUsed = false,
      IsRevoked = false,
      UserId = userId,
      AddedDate = DateTime.UtcNow,
      ExpiryDate = DateTime.UtcNow.AddMonths(_jwtSettings.RefreshTokenExpirationInMonths),
      Token = GenerateRefreshTokenString()
    };

    await _dbContext.RefreshTokens.AddAsync(refreshToken);
    await _dbContext.SaveChangesAsync();

    return refreshToken;
  }

  public async Task<bool> ValidateRefreshToken(string refreshToken, string jwtId)
  {
    var storedRefreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == refreshToken);

    if (storedRefreshToken == null)
    {
      return false;
    }

    if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
    {
      return false;
    }

    if (storedRefreshToken.IsUsed)
    {
      return false;
    }

    if (storedRefreshToken.IsRevoked)
    {
      return false;
    }

    if (storedRefreshToken.JwtId != jwtId)
    {
      return false;
    }

    return true;
  }

  private async Task<JwtSecurityToken> CreateJwtToken(IdentityUser user)
  {
    var userClaims = await _userManager.GetClaimsAsync(user);
    var roles = await _userManager.GetRolesAsync(user);

    var claims = new List<Claim>
    {
      new Claim(ClaimTypes.Name, user.UserName),
      new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
      new Claim(ClaimTypes.NameIdentifier, user.Id)
    };

    claims.AddRange(userClaims);
    foreach (var role in roles)
    {
      claims.Add(new Claim(ClaimTypes.Role, role));
    }

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
      issuer: _jwtSettings.ValidIssuer,
      audience: _jwtSettings.ValidAudience,
      claims: claims,
      expires: DateTime.Now.AddMinutes(_jwtSettings.TokenExpirationInMinutes),
      signingCredentials: creds);

    return token;
  }

  private string GenerateRefreshTokenString()
  {
    var randomNumber = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
      rng.GetBytes(randomNumber);
      return Convert.ToBase64String(randomNumber);
    }
  }

  private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
  {
    var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
    dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
    return dateTimeVal;
  }
}