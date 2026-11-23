function Get-ServerCertificateValidation {
    <#
    .SYNOPSIS
    Get HTTPS certificate and chain information for Url

    .DESCRIPTION
    Obtains certificate data from .Net HttpClient and builds certificate chain to
    verify validity and revocation status

    .PARAMETER Url
    Url to check

    .PARAMETER FollowRedirect
    Follow HTTP redirects

    .EXAMPLE
    PS> Get-ServerCertificateValidation -Url https://expired.badssl.com

    #>
    Param(
        [Parameter(Mandatory = $true)]
        $Url,
        [switch]$FollowRedirect
    )
    $source = @'
using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DNSHealth {

    public class CertValidation {
        public HttpResponseMessage HttpResponse;
        public X509Certificate2 Certificate;
        public X509Chain Chain;
        public SslPolicyErrors SslErrors;
    }

    public static class CertificateCheck {
        public static CertValidation GetServerCertificate(string url, bool allowredirect=false)
        {
            CertValidation certvalidation = new CertValidation();
            var httpClientHandler = new HttpClientHandler
            {
                AllowAutoRedirect = allowredirect,
                ServerCertificateCustomValidationCallback = (requestMessage, cert, chain, sslErrors) =>
                {
                    X509Chain ch = new X509Chain();
                    ch.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                    ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    ch.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                    //ch.ChainPolicy.DisableCertificateDownloads = true;
                    certvalidation.Certificate = new X509Certificate2(cert);
                    ch.Build(cert);
                    certvalidation.Chain = ch;
                    certvalidation.SslErrors = sslErrors;
                    return true;
                }
            };

            var httpClient = new HttpClient(httpClientHandler);
            HttpResponseMessage HttpResponse = Task.Run(async() => await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url))).Result;
            certvalidation.HttpResponse = HttpResponse;
            return certvalidation;
        }
    }
}
'@
    try {
        if (!('DNSHealth.CertificateCheck' -as [type])) {
            Add-Type -TypeDefinition $source -Language CSharp
        }
    }

    catch { Write-Verbose $_.Exception.Message }

    [DNSHealth.CertificateCheck]::GetServerCertificate($Url, $FollowRedirect)
}
