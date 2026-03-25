using Xunit;
using Philiprehberger.EncryptionKit;

namespace Philiprehberger.EncryptionKit.Tests;

public class EncryptionOptionsTests
{
    [Fact]
    public void Defaults_IterationsIs100000()
    {
        var options = new EncryptionOptions();

        Assert.Equal(100_000, options.Iterations);
    }

    [Fact]
    public void Defaults_SaltLengthIs16()
    {
        var options = new EncryptionOptions();

        Assert.Equal(16, options.SaltLength);
    }

    [Fact]
    public void Defaults_NonceLengthIs12()
    {
        var options = new EncryptionOptions();

        Assert.Equal(12, options.NonceLength);
    }

    [Fact]
    public void Defaults_TagLengthIs16()
    {
        var options = new EncryptionOptions();

        Assert.Equal(16, options.TagLength);
    }

    [Fact]
    public void Constructor_WithCustomValues_SetsProperties()
    {
        var options = new EncryptionOptions(
            Iterations: 50_000,
            SaltLength: 32,
            NonceLength: 16,
            TagLength: 12);

        Assert.Equal(50_000, options.Iterations);
        Assert.Equal(32, options.SaltLength);
        Assert.Equal(16, options.NonceLength);
        Assert.Equal(12, options.TagLength);
    }
}
