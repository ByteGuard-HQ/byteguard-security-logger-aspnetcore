using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger upload events with HttpContext enrichment.
/// </summary>
public static class UploadHttpContextExtensions
{
    /// <summary>
    /// Record a successful upload event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileName">File name.</param>
    /// <param name="fileType">File type.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadComplete(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? fileName,
        string? fileType,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUploadComplete(message, userId, fileName, fileType, httpContext, new(), args);
    }

    /// <summary>
    /// Record a successful upload event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileName">File name.</param>
    /// <param name="fileType">File type.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadComplete(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? fileName,
        string? fileType,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUploadComplete(message, userId, fileName, fileType, metadata, args);
    }

    /// <summary>
    /// Record a successful file storage event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original storage location.</param>
    /// <param name="to">New storage location.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadStored(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? from,
        string? to,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUploadStored(message, userId, from, to, httpContext, new(), args);
    }

    /// <summary>
    /// Record a successful file storage event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original storage location.</param>
    /// <param name="to">New storage location.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadStored(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? from,
        string? to,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUploadStored(message, userId, from, to, metadata, args);
    }

    /// <summary>
    /// Record the results of a file validation process.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="filename">File name.</param>
    /// <param name="validationType">Validation type (e.g. virusscan, signature, size, etc.).</param>
    /// <param name="result">Validation result (e.g. FAILED, incomplete, passed).</param>
    /// <param name="level">Log level.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadValidation(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? filename,
        string? validationType,
        string? result,
        LogLevel level,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUploadValidation(message, userId, filename, validationType, result, level, httpContext, new(), args);
    }

    /// <summary>
    /// Record the results of a file validation process.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="filename">File name.</param>
    /// <param name="validationType">Validation type (e.g. virusscan, signature, size, etc.).</param>
    /// <param name="result">Validation result (e.g. FAILED, incomplete, passed).</param>
    /// <param name="level">Log level.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadValidation(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? filename,
        string? validationType,
        string? result,
        LogLevel level,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUploadValidation(message, userId, filename, validationType, result, level, metadata, args);
    }

    /// <summary>
    /// Record a file deletion event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileId">File identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadDelete(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? fileId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUploadDelete(message, userId, fileId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a file deletion event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileId">File identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadDelete(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? fileId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUploadDelete(message, userId, fileId, metadata, args);
    }
}
