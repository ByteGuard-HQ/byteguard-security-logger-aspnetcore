# ByteGuard.SecurityLogger.AspNetCore ![NuGet Version](https://img.shields.io/nuget/v/ByteGuard.SecurityLogger.AspNetCore)

`ByteGuard.SecurityLogger.AspNetCore` adds ASP.NET Core-aware logging methods on top of [`ByteGuard.SecurityLogger`](https://github.com/ByteGuard-HQ/byteguard-security-logger).

It exposes the same OWASP Logging Vocabulary event methods as the core package, but with an `HttpContext`-based variant suffixed with **`FromHttp`** (e.g. `LogAuthnLoginSuccessFromHttp(...)`). These methods use `HttpContext` to automatically populate the logging scope fields according to the OWASP Logging Vocabulary format and the `SecurityEventMetadata` model in the core package

## Getting Started

### Installation

This package is published and installed via [NuGet](https://www.nuget.org/packages/ByteGuard.SecurityLogger.AspNetCore).

Reference the package in your project:

```bash
dotnet add package ByteGuard.SecurityLogger.AspNetCore
```

## Usage

Log your security events and populate the security event metadata from the `HttpContext`:

```csharp
public class MyService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<MyController> _logger;

    public MyService(
        IHttpContextAccessor httpContextAccessor,
        ILogger<MyController> logger)
    {
        _logger = logger;
        _httpContextAccessor = httpContextAccessor
    }

    public void MyFunction()
    {
        // Create configuration instance
        var config = new SecurityLoggerConfiguration
        {
            AppId = "MyApp"
        };

        // Create security logger instance
        var securityLogger = _logger.AsSecurityLogger(config);

        // Log you security event
        var user = _httpContextAccessor.HttpContext.User.Identity.Name;
        securityLogger.AuthnLoginSuccessFromHttp(
            "User {UserId} successfully logged in.",
            userId: user,
            httpContext, _httpContextAccessor.HttpContext
            args: user.Id
        );

        // ...
    }
}
```

## Populated properties

The following properties of the `SecurityEventMetadata` are populated via the `HttpContext`:

- `UserAgent`
- `SourceIp`
- `HostIp`
- `Hostname`
- `Protocol`
- `Port`
- `RequestUri`
- `RequestMethod`

These map into the same structured scope keys that the core package uses via `SecurityEventMetadata`, so your logs remain consistent whether you log from web requests or from background services.

### Predefined values in metadata

`FromHttp` methods are avaiable in two variants:

- One that only uses the `HttpContext` to populate metadata
- Ont that additionally accepts a predefined `SecurityEventMetadata`

When you pass a `SecurityEventMetadata` instance, any values you set explicitly take precedence over values derived from `HttpContext`. Only missing metadata fields will be filled from the HTTP request.

**Example**

```csharp
var securityEventMetadata = new SecurityEventMetadata
{
    Hostname = "my-custom-host.com"
}

// Assume: HttpContext.Request.Host = "my-host.com"

securityLogger.LogAuthnSuccessFromHttp(
    "User {UserId} successfully logged in.",
    userId: userId,
    httpContext: HttpContext,
    metadata: securityEventMetadata,
    args: userId
);

// Resulting scope/metadata includes:
// - Hostname = "my-custom-host.com" (your value wins)
// - Other fields may still be populated from HttpContext (source IP, URI, method, etc.)
```

### Reverse proxies and real client IPs

If your app runs behind a reverse proxy / load balancer, `HttpContext.Connection.RemoteIpAddress` may reflect the proxy rather than the real client.

If you want accurate client IPs, ensure your app is configured to process forwarded headers (_common in production hosting setups_). The `FromHttp` methods can only log the IP that ASP.NET Core exposes to the app.

## Supported events

All events supported by the core [`ByteGuard.SecurityLogger`](https://github.com/ByteGuard-HQ/byteguard-security-logger) is also supported by the `ByteGuard.SecurityLogger.AspNetCore` extensions package. All supported events can be seen in the [WIKI](https://github.com/ByteGuard-HQ/byteguard-security-logger/wiki/Supported-events)

## License

_ByteGuard.SecurityLogger.AspNetCore is Copyright © ByteGuard Contributors - Provided under the MIT license._
