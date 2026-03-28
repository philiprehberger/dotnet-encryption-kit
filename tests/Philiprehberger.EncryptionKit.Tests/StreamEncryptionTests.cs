using Xunit;
using System.Security.Cryptography;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class StreamEncryptionTests
{
    [Fact]
    public async Task EncryptDecryptStreamAsync_SmallData_RoundTripsSuccessfully()
    {
        var originalData = "Hello, Stream Encryption!"u8.ToArray();
        var password = "stream-password-123";

        using var inputStream = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();

        await Encryption.EncryptStreamAsync(inputStream, encryptedStream, password);

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();

        await Encryption.DecryptStreamAsync(encryptedStream, decryptedStream, password);

        Assert.Equal(originalData, decryptedStream.ToArray());
    }

    [Fact]
    public async Task EncryptDecryptStreamAsync_LargeData_RoundTripsSuccessfully()
    {
        var originalData = new byte[250_000]; // Larger than the 80KB chunk size
        Random.Shared.NextBytes(originalData);
        var password = "large-data-password";

        using var inputStream = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();

        await Encryption.EncryptStreamAsync(inputStream, encryptedStream, password);

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();

        await Encryption.DecryptStreamAsync(encryptedStream, decryptedStream, password);

        Assert.Equal(originalData, decryptedStream.ToArray());
    }

    [Fact]
    public async Task EncryptDecryptStreamAsync_EmptyData_RoundTripsSuccessfully()
    {
        var originalData = Array.Empty<byte>();
        var password = "empty-password";

        using var inputStream = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();

        await Encryption.EncryptStreamAsync(inputStream, encryptedStream, password);

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();

        await Encryption.DecryptStreamAsync(encryptedStream, decryptedStream, password);

        Assert.Equal(originalData, decryptedStream.ToArray());
    }

    [Fact]
    public async Task DecryptStreamAsync_WrongPassword_ThrowsCryptographicException()
    {
        var originalData = "secret data"u8.ToArray();

        using var inputStream = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();

        await Encryption.EncryptStreamAsync(inputStream, encryptedStream, "correct-password");

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => Encryption.DecryptStreamAsync(encryptedStream, decryptedStream, "wrong-password"));
    }

    [Fact]
    public async Task EncryptStreamAsync_NullInput_ThrowsArgumentNullException()
    {
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => Encryption.EncryptStreamAsync(null!, output, "password"));
    }

    [Fact]
    public async Task DecryptStreamAsync_NullOutput_ThrowsArgumentNullException()
    {
        using var input = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => Encryption.DecryptStreamAsync(input, null!, "password"));
    }

    [Fact]
    public async Task EncryptDecryptStreamAsync_WithCustomOptions_RoundTripsSuccessfully()
    {
        var originalData = "custom options stream test"u8.ToArray();
        var password = "custom-password";
        var options = new EncryptionOptions(Iterations: 10_000);

        using var inputStream = new MemoryStream(originalData);
        using var encryptedStream = new MemoryStream();

        await Encryption.EncryptStreamAsync(inputStream, encryptedStream, password, options);

        encryptedStream.Position = 0;
        using var decryptedStream = new MemoryStream();

        await Encryption.DecryptStreamAsync(encryptedStream, decryptedStream, password, options);

        Assert.Equal(originalData, decryptedStream.ToArray());
    }
}
