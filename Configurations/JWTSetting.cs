namespace IdentityJWTDemo.Configurations;

public class JWTSetting
{
  public string Secret { get; set; } = null!;
  public string ValidIssuer { get; set; } = null!;
  public string ValidAudience { get; set; } = null!;
  public int TokenExpirationInMinutes { get; set; }
  public int RefreshTokenExpirationInMonths { get; set; }
}
