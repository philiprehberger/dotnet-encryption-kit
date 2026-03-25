using Xunit;
using System.Security.Cryptography;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class EncryptionTests
{
    [Fact]
    public void EncryptDecrypt_String_RoundTripsSuccessfully()
    {
        var plaintext = "Hello, World!";
        var password = "strong-password-123";

        var encrypted = Encryption.Encrypt(plaintext, password);
        var decrypted = Encryption.Decrypt(encrypted, password);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_ByteArray_RoundTripsSuccessfully()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var password = "strong-password-123";

        var encrypted = Encryption.Encrypt(data, password);
        var decrypted = Encryption.Decrypt(encrypted, password);

        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void Encrypt_WithNullPlaintext_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Encryption.Encrypt((string)null!, "password"));
    }

    [Fact]
    public void Encrypt_WithNullPassword_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Encryption.Encrypt("hello", (string)null!));
    }

    [Fact]
    public void Decrypt_WithWrongPassword_ThrowsCryptographicException()
    {
        var encrypted = Encryption.Encrypt("secret", "correct-password");

        Assert.ThrowsAny<CryptographicException>(() => Encryption.Decrypt(encrypted, "wrong-password"));
    }

    [Fact]
    public void Encrypt_ProducesDifferentCiphertextEachTime()
    {
        var plaintext = "same input";
        var password = "password";

        var encrypted1 = Encryption.Encrypt(plaintext, password);
        var encrypted2 = Encryption.Encrypt(plaintext, password);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void EncryptDecrypt_WithCustomOptions_RoundTripsSuccessfully()
    {
        var options = new EncryptionOptions(Iterations: 10_000);
        var plaintext = "custom options test";
        var password = "password";

        var encrypted = Encryption.Encrypt(plaintext, password, options);
        var decrypted = Encryption.Decrypt(encrypted, password, options);

        Assert.Equal(plaintext, decrypted);
    }
}
