using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger privilege events with HttpContext enrichment.
/// </summary>
public static class PrivilegeHttpContextExtensions
{
    /// <summary>
    /// Record a permission level change.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="fromLevel">Original privilege level.</param>
    /// <param name="toLevel">New privilege level.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogPrivilegePermissionsChanged(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        string? fromLevel,
        string? toLevel,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogPrivilegePermissionsChanged(message, userId, resource, fromLevel, toLevel, httpContext, new(), args);
    }

    /// <summary>
    /// Record a permission level change.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="fromLevel">Original privilege level.</param>
    /// <param name="toLevel">New privilege level.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogPrivilegePermissionsChanged(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? resource,
        string? fromLevel,
        string? toLevel,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogPrivilegePermissionsChanged(message, userId, resource, fromLevel, toLevel, metadata, args);
    }
}
