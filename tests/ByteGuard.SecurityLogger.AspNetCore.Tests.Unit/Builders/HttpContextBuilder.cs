using System.Net;
using Microsoft.AspNetCore.Http;

namespace ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Builders;

public static class HttpContextBuilder
{
    public static (HttpContext, SecurityEventMetadata) GetHttpContext(
        string useragent = "TestUserAgent",
        string sourceIp = "10.10.10.10",
        string hostIp = "11.11.11.11",
        string hostname = "test.com",
        string protocol = "HTTPS",
        int port = 443,
        string requestUri = "/test/path",
        string requestMethod = "GET")
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = useragent;
        context.Connection.RemoteIpAddress = IPAddress.Parse(sourceIp);
        context.Connection.LocalIpAddress = IPAddress.Parse(hostIp);
        context.Request.Host = new HostString(hostname);
        context.Request.Scheme = protocol;
        context.Connection.LocalPort = port;
        context.Request.Path = requestUri;
        context.Request.Method = requestMethod;

        var expectedMetadata = new SecurityEventMetadata
        {
            UserAgent = useragent,
            SourceIp = sourceIp,
            HostIp = hostIp,
            Hostname = hostname,
            Protocol = protocol,
            Port = port.ToString(),
            RequestUri = requestUri,
            RequestMethod = requestMethod
        };

        return (context, expectedMetadata);
    }
}
