using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger input events with HttpContext enrichment.
/// </summary>
public static class InputHttpContextExtensions
{
    /// <summary>
    /// Record an input validation failed event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="fields">Invalid fields.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationFailedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        IEnumerable<string>? fields,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogInputValidationFailedFromHttp(message, fields, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record an input validation failed event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="fields">Invalid fields.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationFailedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        IEnumerable<string>? fields,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogInputValidationFailed(message, fields, userId, metadata, args);
    }

    /// <summary>
    /// Record a discrete input validation fail.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="field">Invalid field.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationDiscreteFailFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? field,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogInputValidationDiscreteFailFromHttp(message, field, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a discrete input validation fail.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="field">Invalid field.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationDiscreteFailFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? field,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogInputValidationDiscreteFail(message, field, userId, metadata, args);
    }
}
