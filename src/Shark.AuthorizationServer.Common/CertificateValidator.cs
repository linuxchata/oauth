using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Abstractions;

namespace Shark.AuthorizationServer.Common;

public sealed class CertificateValidator(ILogger<CertificateValidator> logger) : ICertificateValidator
{
    private readonly ILogger<CertificateValidator> _logger = logger;

    public bool IsValid(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return false;
        }

        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag; // Default
        chain.ChainPolicy.VerificationTime = DateTime.Now;

        var isValid = chain.Build(certificate);

        if (!isValid)
        {
            foreach (var chainStatus in chain.ChainStatus)
            {
                _logger.LogError("Chain error: {StatusInformation}", chainStatus.StatusInformation);
            }
        }

        return isValid;
    }
}