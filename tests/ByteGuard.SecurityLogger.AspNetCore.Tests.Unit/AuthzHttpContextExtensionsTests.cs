using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Builders;
using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Helpers;
using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.AspNetCore.Tests.Unit;

public class AuthzHttpContextExtensionsTests
{
    [Fact(DisplayName = "LogAuthzFailFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogAuthzFailFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogAuthzFailFromHttp("Test message", null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogAuthzFailFromHttp with metadata should not override predefined metadata values")]
    public void LogAuthzFailFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
    {
        // Arrange
        var expectedHostname = "custom.hostname.com";
        var metadata = new SecurityEventMetadata { Hostname = expectedHostname };

        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        expectedMetadata.Hostname = expectedHostname;

        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogAuthzFailFromHttp("Test message", null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogAuthzChangeFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogAuthzChangeFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogAuthzChangeFromHttp("Test message", null, null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogAuthzChangeFromHttp with metadata should not override predefined metadata values")]
    public void LogAuthzChangeFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
    {
        // Arrange
        var expectedHostname = "custom.hostname.com";
        var metadata = new SecurityEventMetadata { Hostname = expectedHostname };

        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        expectedMetadata.Hostname = expectedHostname;

        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogAuthzChangeFromHttp("Test message", null, null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogAuthzAdminFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogAuthzAdminFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogAuthzAdminFromHttp("Test message", null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogAuthzAdminFromHttp with metadata should not override predefined metadata values")]
    public void LogAuthzAdminFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
    {
        // Arrange
        var expectedHostname = "custom.hostname.com";
        var metadata = new SecurityEventMetadata { Hostname = expectedHostname };

        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        expectedMetadata.Hostname = expectedHostname;

        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogAuthzAdminFromHttp("Test message", null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }
}
