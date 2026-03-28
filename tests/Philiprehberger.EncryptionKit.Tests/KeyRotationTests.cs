using Xunit;
using System.Security.Cryptography;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class KeyRotationTests
{
    [Fact]
    public void ReEncrypt_WithValidPasswords_ProducesDecryptableResult()
    {
        var plaintext = "sensitive data";
        var oldPassword = "old-password-123";
        var newPassword = "new-password-456";

        var encrypted = Encryption.Encrypt(plaintext, oldPassword);
        var reEncrypted = Encryption.ReEncrypt(encrypted, oldPassword, newPassword);
        var decrypted = Encryption.Decrypt(reEncrypted, newPassword);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ReEncrypt_OldPasswordNoLongerWorks()
    {
        var plaintext = "sensitive data";
        var oldPassword = "old-password-123";
        var newPassword = "new-password-456";

        var encrypted = Encryption.Encrypt(plaintext, oldPassword);
        var reEncrypted = Encryption.ReEncrypt(encrypted, oldPassword, newPassword);

        Assert.ThrowsAny<CryptographicException>(() => Encryption.Decrypt(reEncrypted, oldPassword));
    }

    [Fact]
    public void ReEncrypt_WithWrongOldPassword_ThrowsCryptographicException()
    {
        var encrypted = Encryption.Encrypt("data", "correct-password");

        Assert.ThrowsAny<CryptographicException>(
            () => Encryption.ReEncrypt(encrypted, "wrong-password", "new-password"));
    }

    [Fact]
    public void ReEncrypt_WithCustomOptions_RoundTripsSuccessfully()
    {
        var plaintext = "custom options rotation";
        var oldPassword = "old-pass";
        var newPassword = "new-pass";
        var options = new EncryptionOptions(Iterations: 10_000);

        var encrypted = Encryption.Encrypt(plaintext, oldPassword, options);
        var reEncrypted = Encryption.ReEncrypt(encrypted, oldPassword, newPassword, options);
        var decrypted = Encryption.Decrypt(reEncrypted, newPassword, options);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ReEncrypt_WithNullCiphertext_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => Encryption.ReEncrypt(null!, "old", "new"));
    }

    [Fact]
    public void ReEncrypt_WithEmptyNewPassword_ThrowsArgumentException()
    {
        var encrypted = Encryption.Encrypt("data", "password");

        Assert.ThrowsAny<ArgumentException>(
            () => Encryption.ReEncrypt(encrypted, "password", ""));
    }
}
