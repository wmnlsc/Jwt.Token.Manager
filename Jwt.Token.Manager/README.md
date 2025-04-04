# Token Management System

The **Token Management System** is a robust and flexible .NET library for managing **JWT access tokens**, **ID tokens**, and **refresh tokens** using **RSA (RS256)** or **HMAC (HS256)**. It simplifies the process of secure token generation, validation, and expiration handling — ideal for building authentication and authorization systems in modern web, mobile, or API-based applications.

---

## ✨ Features

- ✅ Generate **JWT Access Tokens** with user claims.
- 🔁 Generate **Refresh Tokens** with secure hashing for renewal.
- 🆔 Generate **ID Tokens** for OpenID Connect-like scenarios.
- ✅ Validate refresh tokens for expiration and integrity.
- 🔐 Supports **RSA (asymmetric)** or **HMAC (symmetric)** signing.
- 🔄 Multi-Factor Authentication (MFA) compatible.
- ⚙️ Fully configurable via strongly typed options classes (`JwtTokenOptionModel` or `RsaTokenOptions`).
- 🧪 Includes detailed exception handling for invalid or expired tokens.

---

## 🔧 Example Configuration (appsettings.json)
> ⚠️ **Security Tip:** It's highly recommended to use **environment variables** to store sensitive values like file paths and keys instead of placing them directly in `appsettings.json`.
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "RsaTokenOptions": {
    "PrivateKeyPath": "/path/to/private.pem",   // 🔐 Prefer setting via environment variable 
    "PublicKeyPath": "/path/to/public.pem",     // 🔐 Prefer setting via environment variable
    "Issuer": "https://auth.yourdomain.com",
    "Audience": "https://api.yourdomain.com",
    "AccessTokenLifetime": "00:30:00",
    "RefreshTokenLifetime": "7.00:00:00",
    "IdTokenLifetime": "00:15:00"
  }
}
```

---

## 🔐 Generate Access Token

```csharp
var claims = new List<Claim>
{
    new(JwtRegisteredClaimNames.Sub, "user123"),
    new(JwtRegisteredClaimNames.Email, "user@example.com"),
};

string accessToken = tokenManager.GenerateAccessToken(claims);

```

---

## 🔁 Generate Refresh Token

```csharp
RefreshTokenModel refreshToken = tokenManager.GenerateRefreshToken();
```
---

## 🆔 Generate ID Token
```csharp
string idToken = tokenManager.GenerateIdToken(claims);
```

---

## ✅ Validate Refresh Token
```csharp
bool isValid = tokenManager.ValidateRefreshToken(refreshTokenFromClient);
```
---

## 🔐 Security Notes
- Always store the hashed version of refresh tokens in your database.
- Configure your API to reject tampered JWTs by validating the RSA signature.
- If using `HMAC (HS256)`, make sure the `SecretKey` is long and random (at least `256 bits`).
- Avoid long-lived access tokens — use refresh tokens for session persistence.

---

## 🧪 Example: Token Response (from API)
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "idToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "af13uZ0-SOME-BASE64-VALUE-0qZn",
  "expiresIn": 1800
}

```

---

## 🧩 Integration with ASP.NET Core
### ✅ Option 1: RSA (Asymmetric) Integration – RS256
> This is the most secure option, using a private key to sign tokens and a public key to validate them.
`Program.cs Example`
```csharp
var rsaPublic = RSA.Create();
rsaPublic.ImportFromPem(File.ReadAllText(configuration["RsaTokenOptions:PublicKeyPath"]));

builder.Services.Configure<RsaTokenOptions>(configuration.GetSection("RsaTokenOptions"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
            ValidIssuer = configuration["RsaTokenOptions:Issuer"],
            ValidAudience = configuration["RsaTokenOptions:Audience"],
            IssuerSigningKey = new RsaSecurityKey(rsaPublic)
        };
    });

```

## 🔐 Option 2: HMAC (Symmetric) Integration – HS256
> Use this option if you're not using RSA keys. It's easier to set up but the SecretKey must remain private and secure. `Program.cs Example`
```csharp
var secretKey = configuration["JwtTokenOptionModel:SecretKey"];
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

builder.Services.Configure<TokenOptionModel>(configuration.GetSection("TokenOptionModel"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
            ValidIssuer = configuration["JwtTokenOptionModel:Issuer"],
            ValidAudience = configuration["JwtTokenOptionModel:Audience"],
            IssuerSigningKey = key
        };
    });
```
--- 
## Register in `Program.cs`
```csharp
// RSA (Asymmetric)
builder.Services.Configure<RsaTokenOptions>(
    builder.Configuration.GetSection("RsaTokenOptions"));

builder.Services.AddScoped<RsaTokenManager>();


// HMAC (Symmetric)
builder.Services.Configure<TokenOptionModel>(
    builder.Configuration.GetSection("JwtTokenOptionModel"));

builder.Services.AddScoped<JwtTokenManager>();
```

## 📦 Installation

Install the package via NuGet:

```bash
dotnet add package Identity.Jwt.Token.Manager
