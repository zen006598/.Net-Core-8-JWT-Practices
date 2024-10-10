using IdentityJWTDemo.Parameters;
using IdentityJWTDemo.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityJWTDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticateApiController(
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    ILogger<AuthenticateApiController> logger,
    ITokenService tokenService
) : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private ILogger<AuthenticateApiController> _logger = logger;
    private ITokenService _tokenService = tokenService;

    [HttpPost("Login")]
    public async Task<IActionResult> Login([FromBody] LoginParameter loginParameters)
    {
        var user = await _userManager.FindByEmailAsync(loginParameters.Email);
        if (user != null && await _userManager.CheckPasswordAsync(user, loginParameters.Password))
        {
            return Ok(await _tokenService.CreateTokenAsync(user));
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

    [HttpPost("RefreshToken")]
    public async Task<ActionResult> RefreshToken([FromBody] TokenParameter parameter)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest("Invalid payload");
        }

        var result = await _tokenService.VerifyAndGenerateToken(parameter);

        if (result == null)
        {
            return BadRequest("Invalid tokens");
        }

        return Ok(result);
    }
}
