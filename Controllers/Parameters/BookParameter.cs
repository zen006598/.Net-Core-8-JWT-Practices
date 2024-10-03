using System.ComponentModel.DataAnnotations;

namespace IdentityJWTDemo;

public class BookParameter
{
  [Required]
  public string Title { get; set; } = null!;
}
