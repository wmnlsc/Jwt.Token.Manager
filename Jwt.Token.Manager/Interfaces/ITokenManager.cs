using System.Security.Claims;
using Jwt.Token.Manager.Models;

namespace Jwt.Token.Manager.Interfaces;

/// <summary>
/// Defines a contract for managing JSON Web Tokens (JWTs) and refresh tokens.
/// </summary>
/// <remarks>
/// This interface is designed to abstract the implementation of token management, including generating 
/// and validating access tokens, ID tokens, and refresh tokens. It can be implemented in various ways 
/// to support different authentication systems.
/// </remarks>
/// <example>
/// Example usage:
/// <code
///     Claim="{ new Claim(JwtRegisteredClaimNames.Sub, &quot;user123&quot;) };
/// 
/// // Generate tokens
/// var accessToken = tokenManager.GenerateAccessToken(claims);
/// var refreshToken = tokenManager.GenerateRefreshToken();
/// var idToken = tokenManager.GenerateIdToken(claims);
/// 
/// // Validate refresh token
/// var isValid = tokenManager.ValidateRefreshToken(refreshToken);">
/// var tokenManager = new TokenManager(options);
/// var claims = new List
/// </code>
/// </example>
public interface ITokenManager
{
    /// <summary>
    /// Generates a JWT access token with the specified claims.
    /// </summary>
    /// <param name="claims">A collection of claims to include in the token.</param>
    /// <param name="isTwoFactor">Indicates whether the token is for a two-factor authentication session. Defaults to false.</param>
    /// <returns>A signed JWT access token as a string.</returns>
    /// <exception cref="ArgumentException">Thrown when claims are null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the secret key is not configured.</exception>
    string GenerateAccessToken(IEnumerable<Claim> claims, bool isTwoFactor = false);
    
    /// <summary>
    /// Generates a refresh token for renewing access tokens.
    /// </summary>
    /// <returns>A <see cref="RefreshTokenModel"/> containing the public and private tokens along with their expiration time.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the refresh token expiration days are invalid.</exception>
    RefreshTokenModel GenerateRefreshToken();
    
    /// <summary>
    /// Generates a JWT ID token with the specified claims for user identification.
    /// </summary>
    /// <param name="claims">A collection of claims to include in the token.</param>
    /// <returns>A signed JWT ID token as a string.</returns>
    /// <exception cref="ArgumentException">Thrown when claims are null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the secret key is not configured.</exception>
    string GenerateIdToken(IEnumerable<Claim> claims);
    
    /// <summary>
    /// Validates the provided refresh token.
    /// </summary>
    /// <param name="refreshToken">The <see cref="RefreshTokenModel"/> containing the public and private tokens to validate.</param>
    /// <returns>True if the token is valid; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the refresh token is null.</exception>
    bool ValidateRefreshToken(RefreshTokenModel refreshToken);
}