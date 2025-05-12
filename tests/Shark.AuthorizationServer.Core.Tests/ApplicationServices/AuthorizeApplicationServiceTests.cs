using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Moq;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Services;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.ApplicationServices;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Domain.Enumerations;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.Core.Tests.ApplicationServices;

[TestFixture]
public class AuthorizeApplicationServiceTests
{
    private readonly ClaimsPrincipal _userIdentity = new();

    private Mock<IAuthorizeValidator> _authorizeValidatorMock = null!;
    private Mock<IStringGeneratorService> _stringGeneratorServiceMock = null!;
    private Mock<ITokenResponseService> _tokenResponseServiceMock = null!;
    private Mock<IRedirectionService> _redirectionServiceMock = null!;
    private Mock<IClientRepository> _clientRepositoryMock = null!;
    private Mock<IPersistedGrantRepository> _persistedGrantRepositoryMock = null!;
    private Mock<ILogger<AuthorizeApplicationService>> _loggerMock = null!;

    private AuthorizeApplicationService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _authorizeValidatorMock = new Mock<IAuthorizeValidator>();
        _stringGeneratorServiceMock = new Mock<IStringGeneratorService>();
        _tokenResponseServiceMock = new Mock<ITokenResponseService>();
        _redirectionServiceMock = new Mock<IRedirectionService>();
        _clientRepositoryMock = new Mock<IClientRepository>();
        _persistedGrantRepositoryMock = new Mock<IPersistedGrantRepository>();
        _loggerMock = new Mock<ILogger<AuthorizeApplicationService>>();

        _sut = new AuthorizeApplicationService(
          _authorizeValidatorMock.Object,
          _stringGeneratorServiceMock.Object,
          _tokenResponseServiceMock.Object,
          _redirectionServiceMock.Object,
          _clientRepositoryMock.Object,
          _persistedGrantRepositoryMock.Object,
          _loggerMock.Object);
    }

    [Test]
    public void Execute_WhenRequestIsNull_ThrowsArgumentNullException()
    {
        // Arrange
        AuthorizeInternalRequest? request = null;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () => await _sut.Execute(request!, _userIdentity));
    }

    [Test]
    public async Task Execute_WhenClientNotFound_ReturnsBadRequestResponse()
    {
        // Arrange
        var request = new AuthorizeInternalRequest
        {
            ResponseType = ResponseType.Code,
            ClientId = "NonExistentClientId",
            RedirectUri = "RedirectUri",
            Scopes = [],
        };

        _clientRepositoryMock.Setup(x => x.Get(request.ClientId)).ReturnsAsync((Client?)null);

        _authorizeValidatorMock
          .Setup(x => x.ValidateRequest(request, null))
          .Returns(new AuthorizeInternalBadRequestResponse(Error.InvalidClient));

        // Act
        var result = await _sut.Execute(request, _userIdentity) as AuthorizeInternalBadRequestResponse;

        // Assert
        Assert.That(result!.Error.Error, Is.EqualTo(Error.InvalidClient));
    }

    [Test]
    public async Task Execute_WhenValidationFails_ReturnsBadRequestResponse()
    {
        // Arrange
        var request = new AuthorizeInternalRequest
        {
            ResponseType = ResponseType.Code,
            ClientId = "ClientId",
            RedirectUri = "RedirectUri",
            Scopes = [],
        };

        var client = GetClient();

        _clientRepositoryMock.Setup(x => x.Get(request.ClientId)).ReturnsAsync(client);

        _authorizeValidatorMock
          .Setup(x => x.ValidateRequest(request, client))
          .Returns(new AuthorizeInternalBadRequestResponse(Error.InvalidRequest));

        // Act
        var result = await _sut.Execute(request, _userIdentity) as AuthorizeInternalBadRequestResponse;

        // Assert
        Assert.That(result!.Error.Error, Is.EqualTo(Error.InvalidRequest));
    }

    [Test]
    public void Execute_WhenResponseTypeIsUnsupported_ThrowsInvalidOperationException()
    {
        // Arrange
        var request = new AuthorizeInternalRequest
        {

            ResponseType = "unsupported_type",
            ClientId = "ClientId",
            RedirectUri = "RedirectUri",
            Scopes = [],
        };

        var client = GetClient();

        _clientRepositoryMock.Setup(x => x.Get(request.ClientId)).ReturnsAsync(client);

        _authorizeValidatorMock
          .Setup(x => x.ValidateRequest(request, client))
          .Returns((AuthorizeInternalBadRequestResponse)null!);

        // Act & Assert
        var exception = Assert.ThrowsAsync<InvalidOperationException>(
            async () => await _sut.Execute(request, _userIdentity));

        Assert.That(exception!.Message, Is.EqualTo("Unsupported response type unsupported_type"));
    }

    private static Client GetClient()
    {
        return new Client
        {
            ClientName = "Client",
            Enabled = true,
            ClientId = "ClientId",
            ClientSecret = "Secret",
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ClientSecretExpiresAt = DateTimeOffset.UtcNow.AddYears(1).ToUnixTimeSeconds(),
            ClientType = ClientType.Confidential,
            RedirectUris = ["https://localhost/callback"],
            GrantTypes = ["authorization_code"],
            ResponseTypes = ["code"],
            TokenEndpointAuthMethod = "client_secret_basic",
            Scope = ["openid", "profile"],
            Audience = "Audience",
            RegistrationAccessToken = "RegistrationAccessToken",
            RegistrationClientUri = "https://localhost/register",
        };
    }
}