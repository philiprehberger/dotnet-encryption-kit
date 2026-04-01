using System.Security.Cryptography;
using System.Text;

namespace Philiprehberger.EncryptionKit;

/// <summary>
/// A self-describing encrypted envelope that bundles algorithm identifier, version, and ciphertext
/// into a single portable byte array. Parse with <see cref="Open"/> to decrypt.
/// </summary>
public static class SealedEnvelope
{
    private const byte EnvelopeVersion = 0x01;
    private const byte AlgorithmAesGcm = 0x01;

    /// <summary>
    /// Encrypts plaintext into a sealed envelope containing algorithm metadata and ciphertext.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="password">The password for key derivation.</param>
    /// <param name="options">Optional encryption settings.</param>
    /// <returns>A byte array containing the complete sealed envelope.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is null.</exception>
    public static byte[] Seal(byte[] plaintext, string password, EncryptionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(password);

        var opts = options ?? new EncryptionOptions();

        // Derive key
        var salt = RandomNumberGenerator.GetBytes(opts.SaltLength);
        var key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, opts.Iterations, HashAlgorithmName.SHA256, 32);

        // Encrypt with AES-GCM
        var nonce = RandomNumberGenerator.GetBytes(opts.NonceLength);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[opts.TagLength];

        using var aes = new AesGcm(key, opts.TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, opts.AssociatedData);

        // Build envelope: version(1) + algorithm(1) + iterations(4) + saltLen(1) + salt + nonceLen(1) + nonce + tagLen(1) + tag + ciphertext
        using var ms = new MemoryStream();
        ms.WriteByte(EnvelopeVersion);
        ms.WriteByte(AlgorithmAesGcm);
        ms.Write(BitConverter.GetBytes(opts.Iterations));
        ms.WriteByte((byte)salt.Length);
        ms.Write(salt);
        ms.WriteByte((byte)nonce.Length);
        ms.Write(nonce);
        ms.WriteByte((byte)tag.Length);
        ms.Write(tag);
        ms.Write(ciphertext);

        return ms.ToArray();
    }

    /// <summary>
    /// Encrypts a string into a sealed envelope.
    /// </summary>
    /// <param name="plaintext">The plaintext string to encrypt.</param>
    /// <param name="password">The password for key derivation.</param>
    /// <param name="options">Optional encryption settings.</param>
    /// <returns>A byte array containing the complete sealed envelope.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is null.</exception>
    public static byte[] Seal(string plaintext, string password, EncryptionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Seal(Encoding.UTF8.GetBytes(plaintext), password, options);
    }

    /// <summary>
    /// Opens a sealed envelope and returns the decrypted data.
    /// </summary>
    /// <param name="envelope">The sealed envelope byte array to decrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="associatedData">Optional additional authenticated data that must match the data used during sealing.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="envelope"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown when the envelope version or algorithm is unsupported, or decryption fails.</exception>
    public static byte[] Open(byte[] envelope, string password, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(password);

        using var ms = new MemoryStream(envelope);

        var version = ms.ReadByte();
        if (version != EnvelopeVersion)
            throw new CryptographicException($"Unsupported envelope version: {version}");

        var algorithm = ms.ReadByte();
        if (algorithm != AlgorithmAesGcm)
            throw new CryptographicException($"Unsupported algorithm: {algorithm}");

        var iterationsBytes = new byte[4];
        ms.ReadExactly(iterationsBytes);
        var iterations = BitConverter.ToInt32(iterationsBytes);

        var saltLen = ms.ReadByte();
        var salt = new byte[saltLen];
        ms.ReadExactly(salt);

        var nonceLen = ms.ReadByte();
        var nonce = new byte[nonceLen];
        ms.ReadExactly(nonce);

        var tagLen = ms.ReadByte();
        var tag = new byte[tagLen];
        ms.ReadExactly(tag);

        var ciphertext = new byte[ms.Length - ms.Position];
        ms.ReadExactly(ciphertext);

        // Derive key
        var key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);

        // Decrypt
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, tagLen);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

        return plaintext;
    }

    /// <summary>
    /// Opens a sealed envelope and returns the decrypted data as a string.
    /// </summary>
    /// <param name="envelope">The sealed envelope byte array to decrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="associatedData">Optional additional authenticated data that must match the data used during sealing.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="envelope"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown when the envelope version or algorithm is unsupported, or decryption fails.</exception>
    public static string OpenString(byte[] envelope, string password, byte[]? associatedData = null)
    {
        return Encoding.UTF8.GetString(Open(envelope, password, associatedData));
    }
}
