namespace Shark.AuthorizationServer.DomainServices.Configurations;

public sealed class AuthorizationServerSecurityConfiguration
{
    public const string Name = nameof(AuthorizationServerConfiguration);

    public bool UseRsaCertificate { get; set; }

    public string? PublicKeyPath { get; set; }

    public string? PrivateKeyPath { get; set; }

    public string? PublicCertificatePath { get; set; }

    public string? PrivateCertificatePath { get; set; }

    public string? PrivateCertificatePassword { get; set; }

}