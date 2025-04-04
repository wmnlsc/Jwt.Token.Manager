namespace Jwt.Token.Manager.Models;

/// <summary>
/// Represents a refresh token used to renew access tokens in a secure manner.
/// </summary>
/// <remarks>
/// The <see cref="RefreshTokenModel"/> contains both a public and private token, ensuring secure handling 
/// of refresh tokens. The public token is intended for the client, while the private token is securely 
/// stored on the server for validation.
/// </remarks>
/// <example>
/// Example usage:
/// <code>
/// var refreshToken = new RefreshTokenModel(publicToken, privateToken, DateTime.UtcNow.AddDays(7));
/// 
/// Console.WriteLine($"Public Token: {refreshToken.PublicToken}");
/// Console.WriteLine($"Private Token: {refreshToken.PrivateToken}");
/// Console.WriteLine($"Expires On: {refreshToken.ExpiresOn}");
/// </code>
/// </example>
public class RefreshTokenModel(string publicToken, string privateToken, DateTimeOffset expiresOn)
{
    /// <summary>
    /// Gets or sets the public token sent to the client for future access token renewal requests.
    /// </summary>
    public string PublicToken { get; set; } = publicToken;
    
    /// <summary>
    /// Gets or sets the private token stored securely on the server to validate the refresh token.
    /// </summary>
    public string PrivateToken { get; set; } = privateToken;
    
    /// <summary>
    /// Gets or sets the expiration time of the refresh token.
    /// </summary>
    public DateTimeOffset ExpiresOn { get; set; } = expiresOn;
}