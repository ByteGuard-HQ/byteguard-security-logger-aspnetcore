using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger.AspNetCore.Enrichers;

internal static class HttpContextEnricher
{
    internal static void EnrichFromHttpContext(ref SecurityEventMetadata metadata, HttpContext httpContext)
    {
        metadata = metadata with
        {
            UserAgent = metadata.UserAgent ?? httpContext.Request.Headers["User-Agent"].ToString(),
            SourceIp = metadata.SourceIp ?? httpContext.Connection.RemoteIpAddress.ToString(),
            HostIp = metadata.HostIp ?? httpContext.Connection.LocalIpAddress.ToString(),
            Hostname = metadata.Hostname ?? httpContext.Request.Host.ToString(),
            Protocol = metadata.Protocol ?? httpContext.Request.Scheme,
            Port = metadata.Port ?? httpContext.Connection.LocalPort.ToString(),
            RequestUri = metadata.RequestUri ?? httpContext.Request.Path.ToString(),
            RequestMethod = metadata.RequestMethod ?? httpContext.Request.Method
        };
    }
}
