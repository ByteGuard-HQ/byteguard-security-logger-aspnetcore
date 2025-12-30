using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger sensitive events with HttpContext enrichment.
/// </summary>
public static class SensitiveHttpContextExtensions
{
    /// <summary>
    /// Record creation of a sensitive object.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveCreateFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSensitiveCreateFromHttp(message, userId, resource, httpContext, new(), args);
    }

    /// <summary>
    /// Record creation of a sensitive object.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveCreateFromHttp(
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

        securityLogger.LogSensitiveCreate(message, userId, resource, metadata, args);
    }

    /// <summary>
    /// Record access (read) of sensitive data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveReadFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSensitiveReadFromHttp(message, userId, resource, httpContext, new(), args);
    }

    /// <summary>
    /// Record access (read) of sensitive data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveReadFromHttp(
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

        securityLogger.LogSensitiveRead(message, userId, resource, metadata, args);
    }

    /// <summary>
    /// Record modification of sensitive data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveUpdateFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSensitiveUpdateFromHttp(message, userId, resource, httpContext, new(), args);
    }

    /// <summary>
    /// Record modification of sensitive data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveUpdateFromHttp(
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

        securityLogger.LogSensitiveUpdate(message, userId, resource, metadata, args);
    }

    /// <summary>
    /// Record deletion of sensitive data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveDeleteFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSensitiveDeleteFromHttp(message, userId, resource, httpContext, new(), args);
    }

    /// <summary>
    /// Record deletion of sensitive data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveDeleteFromHttp(
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

        securityLogger.LogSensitiveDelete(message, userId, resource, metadata, args);
    }
}
