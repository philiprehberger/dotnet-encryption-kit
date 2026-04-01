using Xunit;
using System.Security.Cryptography;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class SealedEnvelopeTests
{
    [Fact]
    public void SealOpen_String_RoundTripsSuccessfully()
    {
        var plaintext = "Hello, Sealed World!";
        var password = "strong-password-123";

        var envelope = SealedEnvelope.Seal(plaintext, password);
        var decrypted = SealedEnvelope.OpenString(envelope, password);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void SealOpen_ByteArray_RoundTripsSuccessfully()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var password = "strong-password-123";

        var envelope = SealedEnvelope.Seal(data, password);
        var decrypted = SealedEnvelope.Open(envelope, password);

        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void Open_WithWrongPassword_ThrowsCryptographicException()
    {
        var envelope = SealedEnvelope.Seal("secret", "correct-password");

        Assert.ThrowsAny<CryptographicException>(() => SealedEnvelope.Open(envelope, "wrong-password"));
    }

    [Fact]
    public void Seal_WithNullPlaintext_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SealedEnvelope.Seal((byte[])null!, "password"));
    }

    [Fact]
    public void Open_WithAadMismatch_ThrowsCryptographicException()
    {
        var aad = new byte[] { 0x01, 0x02, 0x03 };
        var options = new EncryptionOptions(AssociatedData: aad);

        var envelope = SealedEnvelope.Seal("authenticated data", "password", options);

        var wrongAad = new byte[] { 0x04, 0x05, 0x06 };
        Assert.ThrowsAny<CryptographicException>(() => SealedEnvelope.Open(envelope, "password", wrongAad));
    }

    [Fact]
    public void Seal_StartsWithVersionByte()
    {
        var envelope = SealedEnvelope.Seal("test", "password");

        Assert.Equal(0x01, envelope[0]);
    }
}
