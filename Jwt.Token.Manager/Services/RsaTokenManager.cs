using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Jwt.Token.Manager.Configs;
using Jwt.Token.Manager.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Jwt.Token.Manager.Services;

/// <summary>
/// The <c>RsaTokenManager</c> class provides functionality for securely generating JWT access tokens, refresh tokens,
/// and ID tokens using RSA asymmetric encryption. It supports private key signing and optional public key validation.
/// </summary>
/// <remarks>
/// This class is intended for use in authentication systems that leverage RSA for signing JWTs. It uses configuration
/// from the <see cref="RsaTokenOptions"/> class, which includes key paths, issuer, audience, and token lifetimes.
/// The manager ensures secure handling of token creation and validation using RSA cryptography.
/// </remarks>
/// <example>
/// Example usage:
/// <code>
/// var tokenManager = new RsaTokenManager(rsaTokenOptions);
/// var claims = new List&lt;Claim&gt; { new Claim(JwtRegisteredClaimNames.Sub, "user123") };
/// var accessToken = tokenManager.GenerateAccessToken(claims);
/// var refreshToken = tokenManager.GenerateRefreshToken();
/// var idToken = tokenManager.GenerateIdToken(claims);
/// var isValid = tokenManager.ValidateRefreshToken(refreshToken);
/// </code>
/// </example>

public class RsaTokenManager(IOptions<RsaTokenOptions> options)
{
    /// <summary>
    /// Generates a JWT access token using RSA signing, based on the provided claims and configuration.
    /// </summary>
    /// <param name="claims">The claims to include in the token.</param>
    /// <param name="isTwoFactor">Indicates whether the token is intended for two-factor authentication flow.</param>
    /// <returns>A signed JWT access token string.</returns>
    /// <exception cref="ArgumentException">Thrown when claims are null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the RSA private key is missing or invalid.</exception>
    public string GenerateAccessToken(IEnumerable<Claim> claims, bool isTwoFactor = false)
    {
        if (claims == null)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        var claimsList = claims as Claim[] ?? claims.ToArray();
        if (claimsList.Length == 0)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        var privateKeyPath = options.Value.PrivateKeyPath;
        if (string.IsNullOrWhiteSpace(privateKeyPath) || !File.Exists(privateKeyPath))
            throw new InvalidOperationException("Secret Key is not configured.");
        
        using var rsaPrivateKey = RsaTokenConfig.LoadRsaKey(privateKeyPath);
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsaPrivateKey), SecurityAlgorithms.RsaSha256);

        var now = DateTime.UtcNow;
        var expires = isTwoFactor
            ? now.AddMinutes(10)
            : now.Add(options.Value.AccessTokenLifetime);

        var tokenDescription = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claimsList),
            Expires = expires,
            Issuer = options.Value.Issuer,
            Audience = options.Value.Audience,
            NotBefore = now,
            SigningCredentials = signingCredentials
        };

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescription);
            return tokenHandler.WriteToken(securityToken);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("An error occurred while generating the access token.", ex);
        }
    }
    
    /// <summary>
    /// Generates a cryptographically secure refresh token and hashes it for safe storage.
    /// </summary>
    /// <returns>A <see cref="RefreshTokenModel"/> containing the raw token, its hashed representation, and expiration time.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the refresh token lifetime is invalid or zero.</exception>
    public RefreshTokenModel GenerateRefreshToken()
    {
        var now = DateTime.UtcNow;
        if (options.Value.RefreshTokenLifetime <= TimeSpan.Zero)
            throw new InvalidOperationException("Refresh token expiration days must be greater than zero.");

        try
        {
            var publicToken = CreateRefreshToken();
            var privateToken = HashRefreshToken(publicToken);
            var expiryTime = now.Add(options.Value.RefreshTokenLifetime);
            return new RefreshTokenModel(publicToken, privateToken, expiryTime);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("An error occurred while generating the refresh token.", ex);
        }
    }
    
    /// <summary>
    /// Generates a signed JWT ID token using RSA for user identification and OpenID Connect compatibility.
    /// </summary>
    /// <param name="claims">The claims to embed in the token.</param>
    /// <returns>A signed JWT ID token string.</returns>
    /// <exception cref="ArgumentException">Thrown when claims are null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the RSA private key path is not configured or invalid.</exception>
    public string GenerateIdToken(IEnumerable<Claim> claims)
    {
        if (claims == null)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        var claimsList = claims as Claim[] ?? claims.ToArray();
        if (claimsList.Length == 0)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        var privateKeyPath = options.Value.PrivateKeyPath;
        if (string.IsNullOrWhiteSpace(privateKeyPath) || !File.Exists(privateKeyPath))
            throw new InvalidOperationException("Secret Key is not configured.");
        
        using var rsaPrivateKey = RsaTokenConfig.LoadRsaKey(privateKeyPath);
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsaPrivateKey), SecurityAlgorithms.RsaSha256);
        
        var now = DateTime.UtcNow;
        var expires = now.Add(options.Value.IdTokenLifetime);
        
        var tokenDescription = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claimsList),
            Expires = expires,
            Issuer = options.Value.Issuer,
            Audience = options.Value.Audience,
            NotBefore = now,
            SigningCredentials = signingCredentials
        };

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescription);
            return tokenHandler.WriteToken(securityToken);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("An error occurred while generating the id token.", ex);
        }
    }
    
    /// <summary>
    /// Validates a refresh token by comparing its hashed value and checking its expiration time.
    /// </summary>
    /// <param name="refreshToken">The refresh token model to validate.</param>
    /// <returns><c>true</c> if the token is valid and not expired; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the provided refresh token is null.</exception>
    public bool ValidateRefreshToken(RefreshTokenModel refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        var clientToken = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken.PublicToken)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return refreshToken.PrivateToken == clientToken && refreshToken.ExpiresOn > DateTimeOffset.UtcNow;
    }
    
    /// <summary>
    /// Creates a secure, URL-safe, base64-encoded random token suitable for use as a refresh token.
    /// </summary>
    /// <returns>A randomly generated refresh token string.</returns>
    private static string CreateRefreshToken()
    {
        var random = new byte[32];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(random);
        return Convert.ToBase64String(random).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
    
    /// <summary>
    /// Computes a SHA-256 hash of the provided refresh token and encodes it in a URL-safe base64 format.
    /// </summary>
    /// <param name="token">The original refresh token to hash.</param>
    /// <returns>A hashed, URL-safe version of the refresh token.</returns>
    private static string HashRefreshToken(string token) 
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}