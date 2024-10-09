using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityJWTDemo.Data;
using IdentityJWTDemo.Models;
using IdentityJWTDemo.Parameters;
using IdentityJWTDemo.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityJWTDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticateApiController(
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    IConfiguration configuration,
    ILogger<AuthenticateApiController> logger,
    ApplicationDbContext dbContext,
    TokenValidationParameters tokenValidationParams
) : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly IConfiguration _configuration = configuration;
    private ILogger<AuthenticateApiController> _logger = logger;
    private ApplicationDbContext _dbContext = dbContext;
    private readonly TokenValidationParameters _tokenValidationParams = tokenValidationParams;

    private readonly int AuthTokenExpireTimeMins = 15;
    private readonly int RefreshTokenExpireTimeMonths = 6;

    [HttpPost("Login")]
    public async Task<ActionResult> Login([FromBody] LoginParameter loginParameters)
    {
        var user = await _userManager.FindByEmailAsync(loginParameters.Email);
        if (user != null && await _userManager.CheckPasswordAsync(user, loginParameters.Password))
        {
            return Ok(await CreateTokenAsync(user));
        }
        return Unauthorized();
    }

    [HttpPost("Register")]
    public async Task<ActionResult> Register([FromBody] RegisterParameter parameters)
    {
        var userExists = await _userManager.FindByEmailAsync(parameters.Email);
        if (userExists != null)
            return BadRequest(new
            {
                Status = "Error",
                Message = "User already exists!"
            });

        IdentityUser user = new()
        {
            Email = parameters.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = parameters.Username
        };
        var result = await _userManager.CreateAsync(user, parameters.Password);

        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => new { Code = e.Code, Description = e.Description });
            return BadRequest(new
            {
                Status = "Error",
                Message = "User creation failed!",
                Errors = errors
            });
        }

        if (!string.IsNullOrEmpty(parameters.Role))
        {
            if (!await _roleManager.RoleExistsAsync(parameters.Role))
            {
                await _roleManager.CreateAsync(new IdentityRole(parameters.Role));
            }

            await _userManager.AddToRoleAsync(user, parameters.Role);
        }


        return Ok(new { Status = "Success", Message = "User created successfully!" });
    }

    [HttpGet("RefreshToken")]
    public async Task<ActionResult> RefreshToken(TokenParameter parameter)
    {
        if (ModelState.IsValid)
        {
            var result = await VerifyAndGenerateToken(parameter);

            if (result == null)
                return BadRequest("Invalid tokens");

            return Ok(result);
        }

        return BadRequest("Invalid payload");
    }

    private async Task<AuthViewModel> CreateTokenAsync(IdentityUser user)
    {
        var userRoles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

        foreach (var userRole in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, userRole));
        }

        var token = CreateJwtSecurityToken(claims);
        var refreshToken = await CreateRefreshToken(token, user);

        return new AuthViewModel
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = refreshToken.Token,
            Success = true
        };
    }

    private JwtSecurityToken CreateJwtSecurityToken(List<Claim> claims)
    {
        var key = _configuration.GetValue<string>("JwtSettings:Secret") ?? throw new ArgumentNullException("JwtSettings:Secret");
        var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));

        var credentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            issuer: _configuration.GetValue<string>("JwtSettings:ValidIssuer"),
            audience: _configuration.GetValue<string>("JwtSettings:ValidAudience"),
            expires: DateTime.Now.AddMinutes(AuthTokenExpireTimeMins),
            claims: claims,
            signingCredentials: credentials);
        return token;
    }

    private async Task<RefreshToken> CreateRefreshToken(JwtSecurityToken token, IdentityUser user)
    {
        var refreshToken = new RefreshToken()
        {
            JwtId = token.Id,
            IsUsed = false,
            IsRevorked = false,
            UserId = user.Id,
            AddedDate = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.AddMonths(RefreshTokenExpireTimeMonths),
            Token = RandomString(25) + Guid.NewGuid()
        };

        await _dbContext.RefreshTokens.AddAsync(refreshToken);
        await _dbContext.SaveChangesAsync();

        return refreshToken;
    }

    private string RandomString(int length)
    {
        var random = new Random();
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        return new string(Enumerable.Repeat(chars, length)
            .Select(x => x[random.Next(x.Length)]).ToArray());
    }

    private async Task<AuthViewModel> VerifyAndGenerateToken(TokenParameter parameter)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        try
        {
            // Validation 1 - Validation JWT token format
            var tokenInVerification = jwtTokenHandler.ValidateToken(parameter.Token, _tokenValidationParams, out var validatedToken);

            // Validation 2 - Validate encryption alg
            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                if (!result)
                    return null;
            }

            // Validation 3 - validate expiry date
            var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

            var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

            if (expiryDate > DateTime.UtcNow)
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "Token has not yet expired" }
                };
            }

            // validation 4 - validate existence of the token
            var storedRefreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == parameter.RefreshToken);

            if (storedRefreshToken == null)
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "Refresh Token does not exist" }
                };
            }

            // Validation 5 - 检查存储的 RefreshToken 是否已过期
            // Check the date of the saved refresh token if it has expired
            if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "Refresh Token has expired, user needs to re-login" }
                };
            }

            // Validation 6 - validate if used
            if (storedRefreshToken.IsUsed)
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "Refresh Token has been used" }
                };
            }

            // Validation 7 - validate if refresh token has revoked
            if (storedRefreshToken.IsRevorked)
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "Refresh Token has been revoked" }
                };
            }

            // Validation 8 - validate JWT token Id
            var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

            if (storedRefreshToken.JwtId != jti)
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "The token doesn't matched the saved token" }
                };
            }

            // update current token to be used
            storedRefreshToken.IsUsed = true;
            _dbContext.RefreshTokens.Update(storedRefreshToken);
            await _dbContext.SaveChangesAsync();

            // 生成一个新的 token
            var user = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
            return await CreateTokenAsync(user);
        }
        catch (Exception ex)
        {
            if (ex.Message.Contains("Lifetime validation failed. The token is expired."))
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "Token has expired please re-login" }
                };
            }
            else
            {
                return new AuthViewModel()
                {
                    Success = false,
                    Errors = new List<string>() { "Something went wrong." }
                };
            }
        }
    }
    private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
    {
        var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();
        return dateTimeVal;
    }
}
