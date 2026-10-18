using System.Security.Cryptography.X509Certificates;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.DomainServices.Services;

public static class SigningCertificateProvider
{
    public static SigningCertificate Get(string certificatePath)
    {
        ArgumentNullException.ThrowIfNull(certificatePath, nameof(certificatePath));

        var certificate = X509CertificateLoader.LoadCertificateFromFile(certificatePath);

        return new SigningCertificate
        {
            X509CertificateChain = Convert.ToBase64String(certificate.RawData),
        };
    }
}