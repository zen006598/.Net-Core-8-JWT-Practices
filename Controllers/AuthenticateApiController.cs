using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityJWTDemo.Data;
using IdentityJWTDemo.Models;
using IdentityJWTDemo.Parameters;
using IdentityJWTDemo.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace IdentityJWTDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticateApiController(
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    IConfiguration configuration,
    ILogger<AuthenticateApiController> logger,
    ApplicationDbContext dbContext
) : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly IConfiguration _configuration = configuration;
    private ILogger<AuthenticateApiController> _logger = logger;
    private ApplicationDbContext _dbContext = dbContext;

    private readonly int AuthTokenExpireTimeMins = 15;
    private readonly int RefreshTokenExpireTimeMonths = 6;

    [HttpPost("Login")]
    public async Task<ActionResult> Login([FromBody] LoginParameter loginParameters)
    {
        var user = await _userManager.FindByEmailAsync(loginParameters.Email);
        if (user != null && await _userManager.CheckPasswordAsync(user, loginParameters.Password))
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

            return Ok(new AuthViewModel
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken.Token,
                Success = true
            });
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
}
