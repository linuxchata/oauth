using System.Security.Claims;

namespace Shark.AuthorizationServer.Core.Tests.ApplicationServices;

[TestFixture]
public class AuthorizeApplicationServiceTests
{
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
        var userIdentity = new ClaimsPrincipal();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
          await _sut.Execute(request!, userIdentity));
    }

    [Test]
    public async Task Execute_WhenClientNotFound_ReturnsValidatorResponse()
    {
        // Arrange
        var request = new AuthorizeInternalRequest
        {
            ClientId = "non-existent-client"
        };
        var userIdentity = new ClaimsPrincipal();
        var expectedResponse = new Mock<IAuthorizeInternalResponse>().Object;

        _clientRepositoryMock
          .Setup(x => x.Get(request.ClientId))
          .ReturnsAsync((Client?)null);

        _authorizeValidatorMock
          .Setup(x => x.ValidateRequest(request, null))
          .Returns(expectedResponse);

        // Act
        var result = await _sut.Execute(request, userIdentity);

        // Assert
        Assert.That(result, Is.EqualTo(expectedResponse));
    }

    [Test]
    public async Task Execute_WhenValidationFails_ReturnsValidatorResponse()
    {
        // Arrange
        var request = new AuthorizeInternalRequest
        {
            ClientId = "test-client"
        };
        var client = new Client();
        var userIdentity = new ClaimsPrincipal();
        var expectedResponse = new Mock<IAuthorizeInternalResponse>().Object;

        _clientRepositoryMock
          .Setup(x => x.Get(request.ClientId))
          .ReturnsAsync(client);

        _authorizeValidatorMock
          .Setup(x => x.ValidateRequest(request, client))
          .Returns(expectedResponse);

        // Act
        var result = await _sut.Execute(request, userIdentity);

        // Assert
        Assert.That(result, Is.EqualTo(expectedResponse));
    }

    [Test]
    public void Execute_WhenResponseTypeIsUnsupported_ThrowsInvalidOperationException()
    {
        // Arrange
        var request = new AuthorizeInternalRequest
        {
            ClientId = "test-client",
            ResponseType = "unsupported_type"
        };
        var client = new Client();
        var userIdentity = new ClaimsPrincipal();

        _clientRepositoryMock
          .Setup(x => x.Get(request.ClientId))
          .ReturnsAsync(client);

        _authorizeValidatorMock
          .Setup(x => x.ValidateRequest(request, client))
          .Returns((IAuthorizeInternalResponse?)null);

        // Act & Assert
        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () =>
          await _sut.Execute(request, userIdentity));

        Assert.That(exception!.Message, Is.EqualTo("Unsupported response type unsupported_type"));
    }
}