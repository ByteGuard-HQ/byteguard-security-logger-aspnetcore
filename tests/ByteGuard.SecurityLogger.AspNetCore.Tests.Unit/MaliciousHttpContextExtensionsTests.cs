using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Builders;
using ByteGuard.SecurityLogger.AspNetCore.Tests.Unit.Helpers;
using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.AspNetCore.Tests.Unit;

public class MaliciousHttpContextExtensionsTests
{
    [Fact(DisplayName = "LogMaliciousExcess404FromHttp without metadata should add HttpContext values to event metadata")]
    public void LogMaliciousExcess404FromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogMaliciousExcess404FromHttp("Test message", null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousExcess404FromHttp with metadata should not override predefined metadata values")]
    public void LogMaliciousExcess404FromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogMaliciousExcess404FromHttp("Test message", null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousExtraneousFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogMaliciousExtraneousFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogMaliciousExtraneousFromHttp("Test message", null, null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousExtraneousFromHttp with metadata should not override predefined metadata values")]
    public void LogMaliciousExtraneousFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogMaliciousExtraneousFromHttp("Test message", null, null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousAttackToolFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogMaliciousAttackToolFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogMaliciousAttackToolFromHttp("Test message", null, null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousAttackToolFromHttp with metadata should not override predefined metadata values")]
    public void LogMaliciousAttackToolFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogMaliciousAttackToolFromHttp("Test message", null, null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousCorsFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogMaliciousCorsFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogMaliciousCorsFromHttp("Test message", null, null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousCorsFromHttp with metadata should not override predefined metadata values")]
    public void LogMaliciousCorsFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogMaliciousCorsFromHttp("Test message", null, null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousDirectReferenceFromHttp without metadata should add HttpContext values to event metadata")]
    public void LogMaliciousDirectReferenceFromHttp_WithoutMetadata_ShouldAddHttpContextValues()
    {
        // Arrange
        (var httpContext, var expectedMetadata) = HttpContextBuilder.GetHttpContext();
        var config = new SecurityLoggerConfiguration { AppId = "TestApp", DisableSourceIpLogging = false };
        var logger = new FakeLogger();
        var securityLogger = new SecurityLogger(logger, config);

        // Act
        securityLogger.LogMaliciousDirectReferenceFromHttp("Test message", null, null, httpContext);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }

    [Fact(DisplayName = "LogMaliciousDirectReferenceFromHttp with metadata should not override predefined metadata values")]
    public void LogMaliciousDirectReferenceFromHttp_WithMetadata_ShouldNotOverridePredefinedValues()
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
        securityLogger.LogMaliciousDirectReferenceFromHttp("Test message", null, null, httpContext, metadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        AssertHelper.MatchingScopeValues(expectedMetadata, scope);
    }
}
