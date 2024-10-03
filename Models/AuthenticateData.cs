using System.ComponentModel.DataAnnotations;

namespace IdentityJWTDemo.Models;

public class AuthenticateDataResponse
{
    public string? Status { get; set; }
    public string? Message { get; set; }
}

public class LoginModel
{
    [EmailAddress]
    [Required(ErrorMessage = "Eamil Address is required")]
    public string Email { get; set; } = null!;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = null!;
}

public class RegisterModel
{
    [Required(ErrorMessage = "User Name is required")]
    public string Username { get; set; } = null!;

    [EmailAddress]
    [Required(ErrorMessage = "Email Address is required")]
    public string Email { get; set; } = null!;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = null!;
    public string Role { get; set; } = UserRoles.User;
}

public static class UserRoles
{
    public const string Admin = "Admin";
    public const string User = "User";
}
