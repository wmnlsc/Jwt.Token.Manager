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
public class JwtTokenOptionModel
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
    /// How long the access token should be valid.
    /// </summary>
    [Required]
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// How long the refresh token should be valid.
    /// </summary>
    [Required]
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromHours(10);

    /// <summary>
    /// How long the ID token should be valid.
    /// </summary>
    [Required]
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
}

/// <summary>
/// Configuration options for RSA-based JWT authentication.
/// </summary>
public class RsaTokenOptions
{
    /// <summary>
    /// Full file system path to the RSA private key used for signing tokens.
    /// </summary>
    [Required]
    public string PrivateKeyPath { get; set; } = null!;

    /// <summary>
    /// Optional path to the public key used for validating tokens.
    /// </summary>
    public string PublicKeyPath { get; set; }  = string.Empty;

    /// <summary>
    /// The token issuer (typically your authentication server URL).
    /// </summary>
    [Required]
    public string Issuer { get; set; } = null!;

    /// <summary>
    /// The intended audience for the token (e.g., your API URL).
    /// </summary>
    [Required]
    public string Audience { get; set; } = null!;

    /// <summary>
    /// How long the access token should be valid.
    /// </summary>
    [Required]
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// How long the refresh token should be valid.
    /// </summary>
    [Required]
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromHours(10);

    /// <summary>
    /// How long the ID token should be valid.
    /// </summary>
    [Required]
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
}
