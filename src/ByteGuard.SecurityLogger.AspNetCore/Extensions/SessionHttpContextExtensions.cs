using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger sequence events with HttpContext enrichment.
/// </summary>
public static class SessionHttpContextExtensions
{
    /// <summary>
    /// Record session creation.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionCreatedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSessionCreatedFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record session creation.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionCreatedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSessionCreated(message, userId, metadata, args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionRenewedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSessionRenewedFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionRenewedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSessionRenewed(message, userId, metadata, args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionExpiredFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? reason,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSessionExpiredFromHttp(message, userId, reason, httpContext, new(), args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionExpiredFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? reason,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSessionExpired(message, userId, reason, metadata, args);
    }

    /// <summary>
    /// Record attempt to use an expired session.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionUseAfterExpireFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSessionUseAfterExpireFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record attempt to use an expired session.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionUseAfterExpireFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSessionUseAfterExpire(message, userId, metadata, args);
    }
}
