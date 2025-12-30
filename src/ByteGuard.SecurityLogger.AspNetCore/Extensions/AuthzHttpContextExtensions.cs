using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger authz events with HttpContext enrichment.
/// </summary>
public static class AuthzHttpContextExtensions
{
    /// <summary>
    /// Record and authorization failure event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzFailFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthzFailFromHttp(message, userId, resource, httpContext, new(), args);
    }

    /// <summary>
    /// Record and authorization failure event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzFailFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthzFail(message, userId, resource, metadata, args);
    }

    /// <summary>
    /// Record an authorization change event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="from">Original authorization.</param>
    /// <param name="to">New authorization.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzChangeFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? from,
        string? to,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthzChangeFromHttp(message, userId, to, from, httpContext, new(), args);
    }

    /// <summary>
    /// Record an authorization change event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="from">Original authorization.</param>
    /// <param name="to">New authorization.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzChangeFromHttp(
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

        securityLogger.LogAuthzChange(message, userId, to, from, metadata, args);
    }

    /// <summary>
    /// Record an authorized administration event (e.g. user privilege change).
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="event">Event description.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzAdminFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? @event,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthzAdminFromHttp(message, userId, @event, httpContext, new(), args);
    }

    /// <summary>
    /// Record an authorized administration event (e.g. user privilege change).
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="event">Event description.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzAdminFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? @event,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthzAdmin(message, userId, @event, metadata, args);
    }
}
