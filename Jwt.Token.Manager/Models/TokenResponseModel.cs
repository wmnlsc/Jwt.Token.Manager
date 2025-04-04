namespace Jwt.Token.Manager.Models;

/// <summary>
/// Represents the response model for token-related operations in an authentication system.
/// </summary>
/// <remarks>
/// This model encapsulates essential information about the generated tokens, including the access token, 
/// optional refresh token, optional ID token, and metadata like the user's ID and whether the token is for 
/// Multi-Factor Authentication (MFA).
/// </remarks>
/// <example>
/// Example usage:
/// <code>
/// var tokenResponse = new TokenResponseModel(
///     userId: "12345",
///     accessToken: "generatedAccessToken",
///     refreshToken: "generatedRefreshToken",
///     idToken: "generatedIdToken",
///     isMfaToken: true
/// );
/// 
/// Console.WriteLine($"UserId: {tokenResponse.UserId}");
/// Console.WriteLine($"AccessToken: {tokenResponse.AccessToken}");
/// Console.WriteLine($"RefreshToken: {tokenResponse.RefreshToken}");
/// Console.WriteLine($"IdToken: {tokenResponse.IdToken}");
/// Console.WriteLine($"IsMfaToken: {tokenResponse.IsMfaToken}");
/// </code>
/// </example>
public class TokenResponseModel(
    string userId,
    string accessToken,
    string? refreshToken = null,
    string? idToken = null,
    bool isMfaToken = false
)
{
    /// <summary>
    /// Gets the unique identifier of the user associated with the tokens.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown if the userId is null or empty.</exception>
    public string UserId { get; } = !string.IsNullOrEmpty(userId) 
        ? userId 
        : throw new ArgumentException("UserId cannot be null or empty.", nameof(userId));
    
    /// <summary>
    /// Gets the generated access token for the user.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown if the accessToken is null or empty.</exception>
    public string AccessToken { get; } = !string.IsNullOrEmpty(accessToken)
        ? accessToken
        : throw new ArgumentException("AccessToken cannot be null or empty.", nameof(accessToken));
    
    /// <summary>
    /// Gets the generated refresh token, if applicable. Null if no refresh token was generated.
    /// </summary>
    public string? RefreshToken { get; } = refreshToken;
    
    /// <summary>
    /// Gets the generated ID token, if applicable. Null if no ID token was generated.
    /// </summary>
    public string? IdToken { get; } = idToken;
    
    /// <summary>
    /// Gets a value indicating whether this token is for Multi-Factor Authentication (MFA).
    /// </summary>
    public bool IsMfaToken { get; } = isMfaToken;
}