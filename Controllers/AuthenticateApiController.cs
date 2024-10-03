using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityJWTDemo.Models;
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
    ILogger<AuthenticateApiController> logger
) : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly IConfiguration _configuration = configuration;
    private ILogger<AuthenticateApiController> _logger = logger;

    [HttpPost("Login")]
    public async Task<ActionResult> Login([FromBody] LoginModel loginParameters)
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

            var token = CreateToken(claims);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }
        return Unauthorized();
    }

    [HttpPost("Register")]
    public async Task<ActionResult> Register([FromBody] RegisterModel parameters)
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

        return Ok(new { Status = "Success", Message = "User created successfully!" });
    }

    private JwtSecurityToken CreateToken(List<Claim> claims)
    {
        var secretkey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            _configuration.GetValue<string>("JwtSettings:Secret")));    // _configuration.GetSection("JwtSettings:Secret").Value)

        var credentials = new SigningCredentials(secretkey, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(   // 亦可使用　SecurityTokenDescriptor　來産生 Token
            issuer: _configuration.GetValue<string>("JwtSettings:ValidIssuer"),
            audience: _configuration.GetValue<string>("JwtSettings:ValidAudience"),
            expires: DateTime.Now.AddDays(1),
            claims: claims,
            signingCredentials: credentials);

        return token;
    }
}
