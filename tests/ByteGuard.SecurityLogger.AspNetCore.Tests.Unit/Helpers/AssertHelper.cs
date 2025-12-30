namespace ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Helpers;

public static class AssertHelper
{
    public static void MatchingScopeValues(SecurityEventMetadata expectedMetadata, IReadOnlyDictionary<string, object?> logScope)
    {
        Assert.Equal(expectedMetadata.UserAgent, logScope["UserAgent"]);
        Assert.Equal(expectedMetadata.SourceIp, logScope["SourceIp"]);
        Assert.Equal(expectedMetadata.HostIp, logScope["HostIp"]);
        Assert.Equal(expectedMetadata.Hostname, logScope["Hostname"]);
        Assert.Equal(expectedMetadata.Protocol, logScope["Protocol"]);
        Assert.Equal(expectedMetadata.Port, logScope["Port"]);
        Assert.Equal(expectedMetadata.RequestUri, logScope["RequestUri"]);
        Assert.Equal(expectedMetadata.RequestMethod, logScope["RequestMethod"]);
    }
}
