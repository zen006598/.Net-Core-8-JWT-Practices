using System.ComponentModel.DataAnnotations;

namespace IdentityJWTDemo.Parameters;

public class LoginParameter
{
    [EmailAddress, Required]
    public string Email { get; set; } = null!;

    [Required]
    public string Password { get; set; } = null!;
}
