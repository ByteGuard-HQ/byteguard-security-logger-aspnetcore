using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Builders;
using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Helpers;
using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.AspNetCore.Tests.Unit;

public class InputHttpContextExtensionsTests
{
    [Fact(DisplayName = "LogInputValidationFailedFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogInputValidationFailedFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogInputValidationFailedFromHttp("Test message", null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogInputValidationFailedFromHttp with metadata should not override predefined metadata values")]
    public void LogInputValidationFailedFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogInputValidationFailedFromHttp("Test message", null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogInputValidationDiscreteFailFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogInputValidationDiscreteFailFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogInputValidationDiscreteFailFromHttp("Test message", null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogInputValidationDiscreteFailFromHttp with metadata should not override predefined metadata values")]
    public void LogInputValidationDiscreteFailFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogInputValidationDiscreteFailFromHttp("Test message", null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }
}
