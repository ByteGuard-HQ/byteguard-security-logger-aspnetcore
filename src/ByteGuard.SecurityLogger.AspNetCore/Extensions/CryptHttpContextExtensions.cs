using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger crypt events with HttpContext enrichment.
/// </summary>
public static class CryptHttpContextExtensions
{
    /// <summary>
    /// Record a decryption failure event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptDecryptFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogCryptDecryptFail(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a decryption failure event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptDecryptFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogCryptDecryptFail(message, userId, metadata, args);
    }

    /// <summary>
    /// Record an encryption failure event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptEncryptFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogCryptEncryptFail(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record an encryption failure event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptEncryptFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogCryptEncryptFail(message, userId, metadata, args);
    }
}
