using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Jwt.Token.Manager.Interfaces;
using Jwt.Token.Manager.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Jwt.Token.Manager.Services;

/// <summary>
/// The TokenManager class provides functionality for generating and validating JWT access tokens, refresh tokens, 
/// and ID tokens. It also includes helper methods for securely handling tokens.
/// </summary>
/// <remarks>
/// This class is designed to work with JWT-based authentication systems. It leverages the Microsoft IdentityModel 
/// and SecurityToken libraries for token creation and validation. It uses options from the 
/// <see cref="TokenOptionModel"/> class to configure essential settings like the secret key, issuer, audience, and 
/// token expiration times.
/// </remarks>
/// <example>
/// Example usage:
/// <code
///     Claim="{ new Claim(JwtRegisteredClaimNames.Sub, &quot;user123&quot;) };
/// var accessToken = tokenManager.GenerateAccessToken(claims);
/// var refreshToken = tokenManager.GenerateRefreshToken();
/// var idToken = tokenManager.GenerateIdToken(claims);
/// var isValid = tokenManager.ValidateRefreshToken(refreshToken);">
/// var tokenManager = new TokenManager(tokenOptions);
/// var claims = new List
/// </code>
/// </example>
public class TokenManager(IOptions<TokenOptionModel> options) : ITokenManager 
{
    /// <summary>
    /// Generates a JWT access token based on the provided claims and configuration.
    /// </summary>
    /// <param name="claims">A collection of claims to include in the token.</param>
    /// <param name="isTwoFactor">Indicates whether the token is for a two-factor authentication session. Defaults to false.</param>
    /// <returns>A signed JWT access token as a string.</returns>
    /// <exception cref="ArgumentException">Thrown when claims are null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the secret key is not configured.</exception>
    public string GenerateAccessToken(IEnumerable<Claim> claims, bool isTwoFactor = false)
    {
        if (claims == null)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        var claimsList = claims as Claim[] ?? claims.ToArray();
        if (claimsList.Length == 0)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        if (string.IsNullOrWhiteSpace(options.Value.SecretKey))
            throw new InvalidOperationException("Secret Key is not configured.");
        
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var expires = isTwoFactor
            ? DateTime.UtcNow.AddMinutes(10)
            : DateTime.UtcNow.AddMinutes(options.Value.AccessTokenExpirationMinutes);

        var tokenDescription = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claimsList),
            Expires = expires,
            Issuer = options.Value.Issuer,
            Audience = options.Value.Audience,
            NotBefore = DateTime.UtcNow,
            SigningCredentials = credentials
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
    /// Generates a refresh token that can be used to renew access tokens.
    /// </summary>
    /// <returns>A <see cref="RefreshTokenModel"/> containing the public and private tokens along with their expiration time.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the refresh token expiration days are invalid.</exception>
    public RefreshTokenModel GenerateRefreshToken()
    {
        if (options.Value.RefreshTokenExpirationDays <= 0)
            throw new InvalidOperationException("Refresh token expiration days must be greater than zero.");

        try
        {
            var publicToken = CreateRefreshToken();
            var privateToken = HashRefreshToken(publicToken);
            var expiryTime = DateTimeOffset.UtcNow.AddDays(options.Value.RefreshTokenExpirationDays);
            return new RefreshTokenModel(publicToken, privateToken, expiryTime);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("An error occurred while generating the refresh token.", ex);
        }
    }

    /// <summary>
    /// Generates a JWT ID token for user identification.
    /// </summary>
    /// <param name="claims">A collection of claims to include in the token.</param>
    /// <returns>A signed JWT ID token as a string.</returns>
    /// <exception cref="ArgumentException">Thrown when claims are null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the secret key is not configured.</exception>
    public string GenerateIdToken(IEnumerable<Claim> claims)
    {
        if (claims == null)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        var claimsList = claims as Claim[] ?? claims.ToArray();
        if (claimsList.Length == 0)
            throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
        
        if (string.IsNullOrWhiteSpace(options.Value.SecretKey))
            throw new InvalidOperationException("Secret Key is not configured.");
        
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var tokenDescription = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claimsList),
            Expires = DateTime.UtcNow.AddMinutes(options.Value.AccessTokenExpirationMinutes),
            Issuer = options.Value.Issuer,
            Audience = options.Value.Audience,
            NotBefore = DateTime.UtcNow,
            SigningCredentials = credentials
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
    /// Validates the provided refresh token by checking its hash and expiration time.
    /// </summary>
    /// <param name="refreshToken">The <see cref="RefreshTokenModel"/> containing the public and private tokens to validate.</param>
    /// <returns>True if the token is valid; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the refresh token is null.</exception>
    public bool ValidateRefreshToken(RefreshTokenModel refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        var clientToken = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken.PublicToken)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return refreshToken.PrivateToken == clientToken && refreshToken.ExpiresOn > DateTimeOffset.UtcNow;
    }

    // Private helpers
    // /// <summary>
    // /// Generates a secure, random refresh token.
    // /// </summary>
    // /// <returns>A URL-safe, base64-encoded refresh token.</returns>
    private static string CreateRefreshToken()
    {
        var random = new byte[32];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(random);
        return Convert.ToBase64String(random).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
    
    /// <summary>
    /// Hashes a refresh token using SHA-256 for secure validation.
    /// </summary>
    /// <param name="token">The refresh token to hash.</param>
    /// <returns>A URL-safe, base64-encoded hash of the refresh token.</returns>
    private static string HashRefreshToken(string token) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(token)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}