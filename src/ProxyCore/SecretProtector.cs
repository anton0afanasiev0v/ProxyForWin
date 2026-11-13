namespace ProxyForWin.Core;

/// <summary>Encrypts/decrypts the upstream password at rest.</summary>
public interface ISecretProtector
{
    string Protect(string plainText);

    string Unprotect(string protectedText);
}

/// <summary>Fallback used on non-Windows builds and in tests. Not a security boundary.</summary>
public sealed class Base64Protector : ISecretProtector
{
    public string Protect(string plainText)
        => "b64:" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(plainText));

    public string Unprotect(string protectedText)
    {
        if (protectedText.StartsWith("b64:", StringComparison.Ordinal))
        {
            return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(protectedText[4..]));
        }

        return protectedText;
    }
}
