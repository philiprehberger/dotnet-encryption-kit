using Xunit;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class KeyGeneratorTests
{
    [Fact]
    public void GenerateKey_Default256Bits_Returns32Bytes()
    {
        var key = KeyGenerator.GenerateKey();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void GenerateKey_128Bits_Returns16Bytes()
    {
        var key = KeyGenerator.GenerateKey(128);

        Assert.Equal(16, key.Length);
    }

    [Fact]
    public void GenerateKey_InvalidSize_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => KeyGenerator.GenerateKey(64));
    }

    [Fact]
    public void GenerateNonce_ReturnsRequestedLength()
    {
        var nonce = KeyGenerator.GenerateNonce(16);

        Assert.Equal(16, nonce.Length);
    }

    [Fact]
    public void GenerateSalt_ReturnsRequestedLength()
    {
        var salt = KeyGenerator.GenerateSalt(32);

        Assert.Equal(32, salt.Length);
    }

    [Fact]
    public void GenerateKey_ProducesDifferentKeysEachTime()
    {
        var key1 = KeyGenerator.GenerateKey();
        var key2 = KeyGenerator.GenerateKey();

        Assert.NotEqual(key1, key2);
    }
}
