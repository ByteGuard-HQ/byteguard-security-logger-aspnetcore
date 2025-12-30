using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger user events with HttpContext enrichment.
/// </summary>
public static class UserHttpContextExtensions
{
    /// <summary>
    /// Record creation of a new user.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="newUserId">New user identifier.</param>
    /// <param name="attributes">New user attributes.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserCreatedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? newUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUserCreatedFromHttp(message, userId, newUserId, attributes, httpContext, new(), args);
    }

    /// <summary>
    /// Record creation of a new user.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="newUserId">New user identifier.</param>
    /// <param name="attributes">New user attributes.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserCreatedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? newUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUserCreated(message, userId, newUserId, attributes, metadata, args);
    }

    /// <summary>
    /// Record update of a user's attributes.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="attributes">User attributes.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserUpdatedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? onUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUserUpdatedFromHttp(message, userId, onUserId, attributes, httpContext, new(), args);
    }

    /// <summary>
    /// Record update of a user's attributes.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="attributes">User attributes.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserUpdatedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? onUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUserUpdated(message, userId, onUserId, attributes, metadata, args);
    }

    /// <summary>
    /// Record archiving of a user.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserArchivedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? onUserId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUserArchivedFromHttp(message, userId, onUserId, httpContext, new(), args);
    }

    /// <summary>
    /// Record archiving of a user.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserArchivedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? onUserId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUserArchived(message, userId, onUserId, metadata, args);
    }

    /// <summary>
    /// Record deletion of a user.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserDeletedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? onUserId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogUserDeletedFromHttp(message, userId, onUserId, httpContext, new(), args);
    }

    /// <summary>
    /// Record deletion of a user.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserDeletedFromHttp(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? onUserId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogUserDeleted(message, userId, onUserId, metadata, args);
    }
}
