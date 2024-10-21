using System.Security.Cryptography.X509Certificates;

namespace Shark.AuthorizationServer.Common.Abstractions;

public interface ICertificateValidator
{
    bool IsValid(X509Certificate2 certificate);
}