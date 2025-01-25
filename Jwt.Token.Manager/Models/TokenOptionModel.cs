#nullable disable    
using System.ComponentModel.DataAnnotations;

namespace Jwt.Token.Manager.Models;

/// <summary>
/// Represents the configuration options required for generating and managing JSON Web Tokens (JWTs).
/// </summary>
/// <remarks>
/// This model is typically bound to a configuration source, such as appsettings.json or environment variables,
/// and provides settings for access tokens, refresh tokens, and ID tokens.
/// </remarks>
/// <example>
/// Example configuration in appsettings.json:
/// <code>
/// {
///   "TokenOptions": {
///     "SecretKey": "YourSuperSecretKey",
///     "Issuer": "https://your-auth-server.com",
///     "Audience": "https://your-api.com",
///     "AccessTokenExpirationMinutes": 60,
///     "RefreshTokenExpirationDays": 14,
///     "IdTokenExpirationMinutes": 30
///   }
/// }
/// </code>
/// Example binding in .NET:
/// <code TokenOptionModel="(builder.Configuration.GetSection(&quot;TokenOptions&quot;));">
/// builder.Services.Configure
/// </code>
/// </example>
public class TokenOptionModel
{
    /// <summary>
    /// Gets or sets the secret key used to sign JWT tokens.
    /// </summary>
    /// <remarks>
    /// This key must be kept secure and should have sufficient entropy to prevent brute-force attacks.
    /// </remarks>
    [Required]
    public string SecretKey { get; set; }
    
    /// <summary>
    /// Gets or sets the issuer of the tokens, typically representing your authentication server.
    /// </summary>
    [Required]
    public string Issuer { get; set; }
    
    /// <summary>
    /// Gets or sets the audience of the tokens, representing the intended recipients (e.g., your API).
    /// </summary>
    [Required]
    public string Audience { get; set; }
    
    /// <summary>
    /// Gets or sets the expiration time (in minutes) for access tokens.
    /// </summary>
    /// <remarks>
    /// Access tokens are typically short-lived to reduce security risks in case of token compromise.
    /// </remarks>
    [Range(1, int.MaxValue)]
    public int AccessTokenExpirationMinutes { get; set; } = 60;
    
    /// <summary>
    /// Gets or sets the expiration time (in days) for refresh tokens.
    /// </summary>
    /// <remarks>
    /// Refresh tokens are longer-lived and used to obtain new access tokens without requiring re-authentication.
    /// </remarks>
    [Range(1, int.MaxValue)]
    public int RefreshTokenExpirationDays { get; set; } = 14;
    
    /// <summary>
    /// Gets or sets the expiration time (in minutes) for ID tokens.
    /// </summary>
    /// <remarks>
    /// ID tokens are used to convey user identity information and are commonly issued alongside access tokens.
    /// </remarks>
    [Range(1, int.MaxValue)]
    public int IdTokenExpirationMinutes { get; set; } = 30;
}