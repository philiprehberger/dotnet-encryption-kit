using Xunit;
using System.Security.Cryptography;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class VersionHeaderTests
{
    [Fact]
    public void Encrypt_ByteArray_StartsWithVersionByte()
    {
        var data = new byte[] { 1, 2, 3 };
        var password = "password";

        var encrypted = Encryption.Encrypt(data, password);

        Assert.Equal(Encryption.CurrentVersion, encrypted[0]);
    }

    [Fact]
    public void CurrentVersion_IsOne()
    {
        Assert.Equal(0x01, Encryption.CurrentVersion);
    }

    [Fact]
    public void Decrypt_WithInvalidVersionByte_ThrowsCryptographicException()
    {
        var data = new byte[] { 1, 2, 3 };
        var password = "password";

        var encrypted = Encryption.Encrypt(data, password);

        // Tamper with the version byte
        encrypted[0] = 0xFF;

        var ex = Assert.Throws<CryptographicException>(
            () => Encryption.Decrypt(encrypted, password));

        Assert.Contains("Unsupported encryption format version", ex.Message);
        Assert.Contains("0xFF", ex.Message);
    }

    [Fact]
    public void Decrypt_WithZeroVersionByte_ThrowsCryptographicException()
    {
        var data = new byte[] { 1, 2, 3 };
        var password = "password";

        var encrypted = Encryption.Encrypt(data, password);

        // Set version to 0x00
        encrypted[0] = 0x00;

        Assert.Throws<CryptographicException>(
            () => Encryption.Decrypt(encrypted, password));
    }

    [Fact]
    public void Decrypt_DataTooShort_ThrowsArgumentException()
    {
        var tooShort = new byte[] { 0x01, 0x02 }; // version + 1 byte, way too short
        var password = "password";

        Assert.Throws<ArgumentException>(
            () => Encryption.Decrypt(tooShort, password));
    }
}
