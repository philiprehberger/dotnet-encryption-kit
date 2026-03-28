using Xunit;
using System.Security.Cryptography;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class AssociatedDataTests
{
    [Fact]
    public void EncryptDecrypt_WithAssociatedData_RoundTripsSuccessfully()
    {
        var plaintext = "authenticated data test";
        var password = "password-123";
        var aad = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var options = new EncryptionOptions(AssociatedData: aad);

        var encrypted = Encryption.Encrypt(plaintext, password, options);
        var decrypted = Encryption.Decrypt(encrypted, password, options);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithMismatchedAssociatedData_ThrowsCryptographicException()
    {
        var plaintext = "authenticated data test";
        var password = "password-123";
        var encryptOptions = new EncryptionOptions(AssociatedData: new byte[] { 0x01, 0x02 });
        var decryptOptions = new EncryptionOptions(AssociatedData: new byte[] { 0x03, 0x04 });

        var encrypted = Encryption.Encrypt(plaintext, password, encryptOptions);

        Assert.ThrowsAny<CryptographicException>(
            () => Encryption.Decrypt(encrypted, password, decryptOptions));
    }

    [Fact]
    public void Decrypt_WithMissingAssociatedData_ThrowsCryptographicException()
    {
        var plaintext = "authenticated data test";
        var password = "password-123";
        var encryptOptions = new EncryptionOptions(AssociatedData: new byte[] { 0x01, 0x02 });
        var decryptOptions = new EncryptionOptions(); // No AAD

        var encrypted = Encryption.Encrypt(plaintext, password, encryptOptions);

        Assert.ThrowsAny<CryptographicException>(
            () => Encryption.Decrypt(encrypted, password, decryptOptions));
    }

    [Fact]
    public void EncryptDecrypt_WithNullAssociatedData_RoundTripsSuccessfully()
    {
        var plaintext = "no aad test";
        var password = "password-123";
        var options = new EncryptionOptions(AssociatedData: null);

        var encrypted = Encryption.Encrypt(plaintext, password, options);
        var decrypted = Encryption.Decrypt(encrypted, password, options);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_ByteArray_WithAssociatedData_RoundTripsSuccessfully()
    {
        var data = new byte[] { 10, 20, 30, 40, 50 };
        var password = "password-123";
        var aad = new byte[] { 0xAA, 0xBB, 0xCC };
        var options = new EncryptionOptions(AssociatedData: aad);

        var encrypted = Encryption.Encrypt(data, password, options);
        var decrypted = Encryption.Decrypt(encrypted, password, options);

        Assert.Equal(data, decrypted);
    }
}
