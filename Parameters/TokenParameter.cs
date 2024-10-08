using System.ComponentModel.DataAnnotations;

namespace IdentityJWTDemo.Parameters;

public class TokenParameter
{
  [Required]
  public string Token { get; set; } = null!;
  [Required]
  public string RefreshToken { get; set; } = null!;
}
