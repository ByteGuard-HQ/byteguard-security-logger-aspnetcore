using ByteGuard.SecurityLogger.AspNetCore.Enrichers;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for SecurityLogger authn events with HttpContext enrichment.
/// </summary>
public static class AuthnHttpContextExtensions
{
    /// <summary>
    /// Record a successful login event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccess(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnLoginSuccess(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a successful login event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccess(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnLoginSuccess(message, userId, metadata, args);
    }

    /// <summary>
    /// Record a successful login event after a previous failure.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="retries">Number of retries before success.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccessAfterFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        int? retries,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnLoginSuccessAfterFail(message, userId, retries, httpContext, new(), args);
    }

    /// <summary>
    /// Record a successful login event after a previous failure.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="retries">Number of retries before success.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccessAfterFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        int? retries,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnLoginSuccessAfterFail(message, userId, retries, metadata, args);
    }

    /// <summary>
    /// Record a failed login event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnLoginFail(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a failed login event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnLoginFail(message, userId, metadata, args);
    }

    /// <summary>
    /// Record a failed login limit being reached event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="maxLimit">Max limit of retries.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFailMax(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        int? maxLimit,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnLoginFailMax(message, userId, maxLimit, httpContext, new(), args);
    }

    /// <summary>
    /// Record a failed login limit being reached event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="maxLimit">Max limit of retries.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFailMax(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        int? maxLimit,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnLoginFailMax(message, userId, maxLimit, metadata, args);
    }

    /// <summary>
    /// Record an account lockout event (e.g. due to multiple failed login attempts).
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="reason">Lock reason.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginLock(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? reason,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnLoginLock(message, userId, reason, httpContext, new(), args);
    }

    /// <summary>
    /// Record an account lockout event (e.g. due to multiple failed login attempts).
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="reason">Lock reason.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginLock(
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

        securityLogger.LogAuthnLoginLock(message, userId, reason, metadata, args);
    }

    /// <summary>
    /// Record a successful password change event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChange(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnPasswordChange(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a successful password change event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChange(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnPasswordChange(message, userId, metadata, args);
    }

    /// <summary>
    /// Record a failed password change event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChangeFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnPasswordChangeFail(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a failed password change event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChangeFail(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnPasswordChangeFail(message, userId, metadata, args);
    }

    /// <summary>
    /// Record a user logged in from one city suddenly appearing in another, too far away.
    /// </summary>
    /// <remarks>
    /// This often indicates and account takeover.
    /// </remarks>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="regionOne">First region.</param>
    /// <param name="regionTwo">Second region.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnImpossibleTravel(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? regionOne,
        string? regionTwo,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnImpossibleTravel(message, userId, regionOne, regionTwo, httpContext, new(), args);
    }

    /// <summary>
    /// Record a user logged in from one city suddenly appearing in another, too far away.
    /// </summary>
    /// <remarks>
    /// This often indicates and account takeover.
    /// </remarks>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="regionOne">First region.</param>
    /// <param name="regionTwo">Second region.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnImpossibleTravel(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? regionOne,
        string? regionTwo,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnImpossibleTravel(message, userId, regionOne, regionTwo, metadata, args);
    }

    /// <summary>
    /// Record a token creation event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="entitlements">Entitlements (e.g. create, read, update, etc.).</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenCreated(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        IEnumerable<string>? entitlements,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnTokenCreated(message, userId, entitlements, httpContext, new(), args);
    }

    /// <summary>
    /// Record a token creation event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="entitlements">Entitlements (e.g. create, read, update, etc.).</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenCreated(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        IEnumerable<string>? entitlements,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnTokenCreated(message, userId, entitlements, metadata, args);
    }

    /// <summary>
    /// Record a token revocation event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenRevoked(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? tokenId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnTokenRevoked(message, userId, tokenId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a token revocation event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenRevoked(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string tokenId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnTokenRevoked(message, userId, tokenId, metadata, args);
    }

    /// <summary>
    /// Record an attempted token reuse event after a token has been revoked.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenReuse(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string? tokenId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnTokenReuse(message, userId, tokenId, httpContext, new(), args);
    }

    /// <summary>
    /// Record an attempted token reuse event after a token has been revoked.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenReuse(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        string tokenId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnTokenReuse(message, userId, tokenId, metadata, args);
    }

    /// <summary>
    /// Record a token deletion event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenDelete(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        params object?[] args)
    {
        securityLogger.LogAuthnTokenDelete(message, userId, httpContext, new(), args);
    }

    /// <summary>
    /// Record a token deletion event.
    /// </summary>
    /// <param name="securityLogger">Security logger.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identificer.</param>
    /// <param name="httpContext">HttpContext.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenDelete(
        this SecurityLogger securityLogger,
        string message,
        string? userId,
        HttpContext httpContext,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        metadata ??= new SecurityEventMetadata();
        HttpContextEnricher.EnrichFromHttpContext(ref metadata, httpContext);

        securityLogger.LogAuthnTokenDelete(message, userId, metadata, args);
    }
}
