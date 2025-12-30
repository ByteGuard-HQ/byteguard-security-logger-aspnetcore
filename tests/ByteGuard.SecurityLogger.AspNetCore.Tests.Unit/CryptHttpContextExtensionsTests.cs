using System;
using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Builders;
using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Helpers;
using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.AspNetCore.Tests.Unit;

public class CryptHttpContextExtensionsTests
{
    [Fact(DisplayName = "LogCryptDecryptFailFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogCryptDecryptFailFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogCryptDecryptFailFromHttp("Test message", null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogCryptDecryptFailFromHttp with metadata should not override predefined metadata values")]
    public void LogCryptDecryptFailFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogCryptDecryptFailFromHttp("Test message", null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogCryptEncryptFailFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogCryptEncryptFailFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogCryptEncryptFailFromHttp("Test message", null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogCryptEncryptFailFromHttp with metadata should not override predefined metadata values")]
    public void LogCryptEncryptFailFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogCryptEncryptFailFromHttp("Test message", null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }
}
