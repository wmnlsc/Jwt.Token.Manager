using System.Security.Cryptography;

namespace Jwt.Token.Manager.Configs;

public static class RsaTokenConfig
{
    public static RSA LoadRsaKey(string keyPath)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(keyPath));
        return rsa;
    }
}