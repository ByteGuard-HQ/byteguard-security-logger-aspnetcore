using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Builders;
using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Helpers;
using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.AspNetCore.Tests.Unit;

public class UploadHttpContextExtensionsTests
{
    [Fact(DisplayName = "LogUploadCompleteFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogUploadCompleteFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogUploadCompleteFromHttp("Test message", null, null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogUploadCompleteFromHttp with metadata should not override predefined metadata values")]
    public void LogUploadCompleteFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogUploadCompleteFromHttp("Test message", null, null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogUploadStoredFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogUploadStoredFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogUploadStoredFromHttp("Test message", null, null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogUploadStoredFromHttp with metadata should not override predefined metadata values")]
    public void LogUploadStoredFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogUploadStoredFromHttp("Test message", null, null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogUploadValidationFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogUploadValidationFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogUploadValidationFromHttp("Test message", null, null, null, null, LogLevel.Information, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogUploadValidationFromHttp with metadata should not override predefined metadata values")]
    public void LogUploadValidationFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogUploadValidationFromHttp("Test message", null, null, null, null, LogLevel.Information, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogUploadDeleteFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogUploadDeleteFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogUploadDeleteFromHttp("Test message", null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogUploadDeleteFromHttp with metadata should not override predefined metadata values")]
    public void LogUploadDeleteFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogUploadDeleteFromHttp("Test message", null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }
}
