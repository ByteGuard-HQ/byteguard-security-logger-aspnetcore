using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger excess events with HttpContext enrichment.
/// </summary>
public static class ExcessHttpContextExtensions
{
    /// <summary>
    /// Record a rate limit or service limit being exceeded event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="max">Maximum allowed requests.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogExcessRateLimitExceededFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        int? max,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogExcessRateLimitExceededFromHttp(message, userId, max, httpContext, new(), args);
    }

    /// <summary>
    /// Record a rate limit or service limit being exceeded event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="max">Maximum allowed requests.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogExcessRateLimitExceededFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        int? max,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogExcessRateLimitExceeded(message, userId, max, metadata, args);
    }
}
