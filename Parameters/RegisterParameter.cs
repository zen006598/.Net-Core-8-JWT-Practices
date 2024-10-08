using System.ComponentModel.DataAnnotations;
using IdentityJWTDemo.Common;

namespace IdentityJWTDemo.Parameters;

public class RegisterParameter
{
    [Required]
    public string Username { get; set; } = null!;

    [EmailAddress, Required]
    public string Email { get; set; } = null!;

    [Required]
    public string Password { get; set; } = null!;
    public string Role { get; set; } = UserRoles.User;
}
