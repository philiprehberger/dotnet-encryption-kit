using System.Security.Cryptography;

namespace Philiprehberger.EncryptionKit;

/// <summary>
/// Generates cryptographically secure keys and nonces for encryption operations.
/// </summary>
public static class KeyGenerator
{
    /// <summary>
    /// Generates a cryptographically secure random key.
    /// </summary>
    /// <param name="bits">The key size in bits. Must be 128, 192, or 256. Defaults to 256.</param>
    /// <returns>A byte array containing the generated key.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="bits"/> is not 128, 192, or 256.</exception>
    public static byte[] GenerateKey(int bits = 256)
    {
        if (bits is not (128 or 192 or 256))
            throw new ArgumentException("Key size must be 128, 192, or 256 bits.", nameof(bits));
        return RandomNumberGenerator.GetBytes(bits / 8);
    }

    /// <summary>
    /// Generates a cryptographically secure random nonce suitable for AES-GCM.
    /// </summary>
    /// <param name="length">The nonce length in bytes. Defaults to 12.</param>
    /// <returns>A byte array containing the generated nonce.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is less than 1.</exception>
    public static byte[] GenerateNonce(int length = 12)
    {
        if (length < 1)
            throw new ArgumentOutOfRangeException(nameof(length), "Nonce length must be at least 1 byte.");
        return RandomNumberGenerator.GetBytes(length);
    }

    /// <summary>
    /// Generates a cryptographically secure random salt for key derivation.
    /// </summary>
    /// <param name="length">The salt length in bytes. Defaults to 16.</param>
    /// <returns>A byte array containing the generated salt.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is less than 1.</exception>
    public static byte[] GenerateSalt(int length = 16)
    {
        if (length < 1)
            throw new ArgumentOutOfRangeException(nameof(length), "Salt length must be at least 1 byte.");
        return RandomNumberGenerator.GetBytes(length);
    }
}
