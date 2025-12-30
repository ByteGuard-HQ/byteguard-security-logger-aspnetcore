using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger sequence events with HttpContext enrichment.
/// </summary>
public static class SequenceHttpContextExtensions
{
    /// <summary>
    /// Record a sequence error (unexpected order of action).
    /// </summary>
    /// <remarks>
    /// Could indicate intentional abuse of the business logic.
    /// </remarks>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSequenceFailFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSequenceFailFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a sequence error (unexpected order of action).
    /// </summary>
    /// <remarks>
    /// Could indicate intentional abuse of the business logic.
    /// </remarks>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSequenceFailFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSequenceFail(message, userId, metadata, args);
    }
}
