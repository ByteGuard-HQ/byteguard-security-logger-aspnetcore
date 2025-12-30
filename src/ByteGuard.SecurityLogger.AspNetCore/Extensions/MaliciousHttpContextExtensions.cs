using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger malicious events with HttpContext enrichment.
/// </summary>
public static class MaliciousHttpContextExtensions
{
    /// <summary>
    /// Record excessive 404 errors.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExcess404FromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? useragent,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogMaliciousExcess404FromHttp(message, ipAddress, useragent, httpContext, new(), args);
    }

    /// <summary>
    /// Record excessive 404 errors.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExcess404FromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? useragent,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogMaliciousExcess404(message, ipAddress, useragent, metadata, args);
    }

    /// <summary>
    /// Record unexpected input or extraneous data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="inputName">Input name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExtraneousFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? inputName,
        string? useragent,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogMaliciousExtraneousFromHttp(message, ipAddress, inputName, useragent, httpContext, new(), args);
    }

    /// <summary>
    /// Record unexpected input or extraneous data.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="inputName">Input name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExtraneousFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? inputName,
        string? useragent,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogMaliciousExtraneous(message, ipAddress, inputName, useragent, metadata, args);
    }

    /// <summary>
    /// Record detection of attack tool usage.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="toolName">Tool name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousAttackToolFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? toolName,
        string? useragent,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogMaliciousAttackToolFromHttp(message, ipAddress, toolName, useragent, httpContext, new(), args);
    }

    /// <summary>
    /// Record detection of attack tool usage.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="toolName">Tool name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousAttackToolFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? toolName,
        string? useragent,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogMaliciousAttackTool(message, ipAddress, toolName, useragent, metadata, args);
    }

    /// <summary>
    /// Record a CORS violation attempt.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="referrer">Referrer.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousCorsFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? referrer,
        string? useragent,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogMaliciousCorsFromHttp(message, ipAddress, referrer, useragent, httpContext, new(), args);
    }

    /// <summary>
    /// Record a CORS violation attempt.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="referrer">Referrer.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousCorsFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? referrer,
        string? useragent,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogMaliciousCors(message, ipAddress, referrer, useragent, metadata, args);
    }

    /// <summary>
    /// Record a direct object reference attempt.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousDirectReferenceFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? useragent,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogMaliciousDirectReferenceFromHttp(message, ipAddress, useragent, httpContext, new(), args);
    }

    /// <summary>
    /// Record a direct object reference attempt.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousDirectReferenceFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? ipAddress,
        string? useragent,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogMaliciousDirectReference(message, ipAddress, useragent, metadata, args);
    }
}
