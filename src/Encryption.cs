using System.Security.Cryptography;
using System.Text;

namespace Philiprehberger.EncryptionKit;

/// <summary>
/// Provides AES-256-GCM encryption and decryption with automatic PBKDF2 key derivation,
/// random nonce generation, and authenticated encryption.
/// </summary>
public static class Encryption
{
    private static readonly EncryptionOptions DefaultOptions = new();

    private const int KeyLength = 32; // 256 bits

    /// <summary>
    /// Encrypts a plaintext string using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="plaintext">The plaintext string to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>A base64-encoded string containing the salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is empty.</exception>
    public static string Encrypt(string plaintext, string password)
    {
        return Encrypt(plaintext, password, DefaultOptions);
    }

    /// <summary>
    /// Encrypts a plaintext string using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="plaintext">The plaintext string to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options.</param>
    /// <returns>A base64-encoded string containing the salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plaintext"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="plaintext"/> or <paramref name="password"/> is empty.</exception>
    public static string Encrypt(string plaintext, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var data = Encoding.UTF8.GetBytes(plaintext);
        var encrypted = Encrypt(data, password, options);

        return Convert.ToBase64String(encrypted);
    }

    /// <summary>
    /// Decrypts a base64-encoded ciphertext string using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="ciphertext">The base64-encoded string containing the salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ciphertext"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ciphertext"/> or <paramref name="password"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password or corrupted data.</exception>
    public static string Decrypt(string ciphertext, string password)
    {
        return Decrypt(ciphertext, password, DefaultOptions);
    }

    /// <summary>
    /// Decrypts a base64-encoded ciphertext string using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="ciphertext">The base64-encoded string containing the salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options matching those used during encryption.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ciphertext"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ciphertext"/> or <paramref name="password"/> is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password or corrupted data.</exception>
    public static string Decrypt(string ciphertext, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(ciphertext);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var data = Convert.FromBase64String(ciphertext);
        var decrypted = Decrypt(data, password, options);

        return Encoding.UTF8.GetString(decrypted);
    }

    /// <summary>
    /// Encrypts a byte array using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>A byte array containing the salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty.</exception>
    public static byte[] Encrypt(byte[] data, string password)
    {
        return Encrypt(data, password, DefaultOptions);
    }

    /// <summary>
    /// Encrypts a byte array using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options.</param>
    /// <returns>A byte array containing the salt, nonce, ciphertext, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty.</exception>
    public static byte[] Encrypt(byte[] data, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var salt = new byte[options.SaltLength];
        RandomNumberGenerator.Fill(salt);

        var key = DeriveKey(password, salt, options.Iterations);

        var nonce = new byte[options.NonceLength];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[data.Length];
        var tag = new byte[options.TagLength];

        using var aes = new AesGcm(key, options.TagLength);
        aes.Encrypt(nonce, data, ciphertext, tag);

        // Pack as: salt + nonce + ciphertext + tag
        var result = new byte[salt.Length + nonce.Length + ciphertext.Length + tag.Length];
        var offset = 0;

        Buffer.BlockCopy(salt, 0, result, offset, salt.Length);
        offset += salt.Length;

        Buffer.BlockCopy(nonce, 0, result, offset, nonce.Length);
        offset += nonce.Length;

        Buffer.BlockCopy(ciphertext, 0, result, offset, ciphertext.Length);
        offset += ciphertext.Length;

        Buffer.BlockCopy(tag, 0, result, offset, tag.Length);

        CryptographicOperations.ZeroMemory(key);

        return result;
    }

    /// <summary>
    /// Decrypts a byte array using AES-256-GCM with PBKDF2 key derivation.
    /// </summary>
    /// <param name="data">The byte array containing the salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> or <paramref name="password"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty or <paramref name="data"/> is too short.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password or corrupted data.</exception>
    public static byte[] Decrypt(byte[] data, string password)
    {
        return Decrypt(data, password, DefaultOptions);
    }

    /// <summary>
    /// Decrypts a byte array using AES-256-GCM with PBKDF2 key derivation and custom options.
    /// </summary>
    /// <param name="data">The byte array containing the salt, nonce, ciphertext, and authentication tag.</param>
    /// <param name="password">The password used for key derivation.</param>
    /// <param name="options">Custom encryption options matching those used during encryption.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/>, <paramref name="password"/>, or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is empty or <paramref name="data"/> is too short.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to an invalid password or corrupted data.</exception>
    public static byte[] Decrypt(byte[] data, string password, EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var headerLength = options.SaltLength + options.NonceLength + options.TagLength;

        if (data.Length < headerLength)
        {
            throw new ArgumentException(
                $"Encrypted data is too short. Expected at least {headerLength} bytes, got {data.Length}.",
                nameof(data));
        }

        var offset = 0;

        var salt = new byte[options.SaltLength];
        Buffer.BlockCopy(data, offset, salt, 0, salt.Length);
        offset += salt.Length;

        var nonce = new byte[options.NonceLength];
        Buffer.BlockCopy(data, offset, nonce, 0, nonce.Length);
        offset += nonce.Length;

        var ciphertextLength = data.Length - headerLength;
        var ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(data, offset, ciphertext, 0, ciphertextLength);
        offset += ciphertextLength;

        var tag = new byte[options.TagLength];
        Buffer.BlockCopy(data, offset, tag, 0, tag.Length);

        var key = DeriveKey(password, salt, options.Iterations);
        var plaintext = new byte[ciphertextLength];

        using var aes = new AesGcm(key, options.TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        CryptographicOperations.ZeroMemory(key);

        return plaintext;
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256);

        return pbkdf2.GetBytes(KeyLength);
    }
}
