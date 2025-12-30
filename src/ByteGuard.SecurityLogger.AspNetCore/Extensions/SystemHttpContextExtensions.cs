using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger system events with HttpContext enrichment.
/// </summary>
public static class SystemHttpContextExtensions
{
    /// <summary>
    /// Record a system startup event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysStartupFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSysStartupFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a system startup event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysStartupFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSysStartup(message, userId, metadata, args);
    }

    /// <summary>
    /// Record a system shutdown event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysShutdownFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSysShutdownFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a system shutdown event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysShutdownFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSysShutdown(message, userId, metadata, args);
    }

    /// <summary>
    /// Record a system restart event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysRestartFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSysRestartFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a system restart event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysRestartFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSysRestart(message, userId, metadata, args);
    }

    /// <summary>
    /// Record a system crash event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysCrashFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSysCrashFromHttp(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a system crash event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysCrashFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSysCrash(message, userId, metadata, args);
    }

    /// <summary>
    /// Record disabling of a system monitor.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorDisabledFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? monitor,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSysMonitorDisabledFromHttp(message, userId, monitor, httpContext, new(), args);
    }

    /// <summary>
    /// Record disabling of a system monitor.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorDisabledFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? monitor,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSysMonitorDisabled(message, userId, monitor, metadata, args);
    }

    /// <summary>
    /// Record enabling of a system monitor.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorEnabledFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? monitor,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogSysMonitorEnabledFromHttp(message, userId, monitor, httpContext, new(), args);
    }

    /// <summary>
    /// Record enabling of a system monitor.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorEnabledFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? monitor,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogSysMonitorEnabled(message, userId, monitor, metadata, args);
    }
}
