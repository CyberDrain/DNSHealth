function Test-HttpsCertificate {
    <#
    .SYNOPSIS
    Test HTTPS certificate for Domain

    .DESCRIPTION
    This function aggregates test results for a domain and subdomains in regards to
    HTTPS certificates

    .PARAMETER Domain
    Domain to check

    .PARAMETER Subdomains
    List of subdomains

    .EXAMPLE
    PS> Test-HttpsCertificate -Domain badssl.com -Subdomains expired, revoked

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [string[]]$Subdomains = @()
    )

    $CertificateTests = [PSCustomObject]@{
        Domain           = $Domain
        UrlsToTest       = [System.Collections.Generic.List[string]]::new()
        Tests            = [System.Collections.Generic.List[object]]::new()
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
    }

    $Urls = [System.Collections.Generic.List[string]]::new()
    $Urls.Add(('https://{0}' -f $Domain)) | Out-Null

    if (($Subdomains | Measure-Object).Count -gt 0) {
        foreach ($Subdomain in $Subdomains) {
            $Urls.Add(('https://{0}.{1}' -f $Subdomain, $Domain)) | Out-Null
        }
    }

    $CertificateTests.UrlsToTest = $Urls

    $CertificateTests.Tests = foreach ($Url in $Urls) {
        $Test = [PSCustomObject]@{
            Hostname         = ''
            Certificate      = ''
            Chain            = ''
            HttpResponse     = ''
            ValidityDays     = 0
            ValidationPasses = [System.Collections.Generic.List[string]]::new()
            ValidationWarns  = [System.Collections.Generic.List[string]]::new()
            ValidationFails  = [System.Collections.Generic.List[string]]::new()
            Errors           = [System.Collections.Generic.List[string]]::new()
        }
        try {
            # Parse URL and extract hostname
            $ParsedUrl = [System.Uri]::new($Url)
            $Hostname = $ParsedUrl.Host

            # Valdiations
            $ValidationPasses = [System.Collections.Generic.List[string]]::new()
            $ValidationWarns = [System.Collections.Generic.List[string]]::new()
            $ValidationFails = [System.Collections.Generic.List[string]]::new()

            # Grab certificate data
            $Validation = Get-ServerCertificateValidation -Url $Url
            # DnsNameList is Windows-only type data, so read the names from the SAN extension
            $DnsNames = foreach ($Extension in $Validation.Certificate.Extensions) {
                if ($Extension -is [System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]) { $Extension.EnumerateDnsNames() }
            }
            $DnsNameList = foreach ($DnsName in $DnsNames) { [PSCustomObject]@{ Punycode = $DnsName; Unicode = $DnsName } }
            $Certificate = $Validation.Certificate | Select-Object FriendlyName, IssuerName, NotBefore, NotAfter, SerialNumber, SignatureAlgorithm, SubjectName, Thumbprint, Issuer, Subject, @{ Name = 'DnsNameList'; Expression = { @($DnsNameList) } }
            $HttpResponse = $Validation.HttpResponse
            $Chain = $Validation.Chain

            $CurrentDate = Get-Date
            $TimeSpan = New-TimeSpan -Start $CurrentDate -End $Certificate.NotAfter

            # Check to see if certificate is contained in the DNS name list
            if ($DnsNames -contains $Hostname -or $DnsNames -contains "*.$Domain") {
                $ValidationPasses.Add(('{0} - Certificate DNS name list contains hostname.' -f $Hostname)) | Out-Null
            }

            else {
                $ValidationFails.Add(('{0} - Certificate DNS name list does not contain hostname' -f $Hostname)) | Out-Null
            }

            # Check certificate validity
            if ($Certificate.NotBefore -ge $CurrentDate) {
                # NotBefore is in the future
                $ValidationFails.Add(('{0} - Certificate is not yet valid.' -f $Hostname)) | Out-Null
            }

            elseif ($Certificate.NotAfter -le $CurrentDate) {
                # NotAfter is in the past
                $ValidationFails.Add(('{0} - Certificate expired {1} day(s) ago.' -f $Hostname, [Math]::Abs($TimeSpan.Days))) | Out-Null
            }

            elseif ($Certificate.NotAfter -ge $CurrentDate -and $TimeSpan.Days -lt 30) {
                # NotAfter is under 30 days away
                $ValidationWarns.Add(('{0} - Certificate will expire in {1} day(s).' -f $Hostname, $TimeSpan.Days)) | Out-Null
            }

            else {
                # Certificate is valid and not expired
                $ValidationPasses.Add(('{0} - Certificate is valid for the next {1} days.' -f $Hostname, $TimeSpan.Days)) | Out-Null
            }

            # Certificate chain errors
            if (($Chain.ChainStatus | Measure-Object).Count -gt 0) {
                foreach ($Status in $Chain.ChainStatus) {
                    $ValidationFails.Add(('{0} - {1}' -f $Hostname, $Status.StatusInformation)) | Out-Null
                }
            }

            # Website status errorr
            if ([int]$HttpResponse.StatusCode -ge 400) {
                $ValidationFails.Add(('{0} - Website responded with: {1}' -f $Hostname, $HttpResponse.ReasonPhrase))
            }

            # Set values and return Test object
            $Test.Hostname = $Hostname
            $Test.Certificate = $Certificate
            $Test.Chain = $Chain
            $Test.HttpResponse = $HttpResponse
            $Test.ValidityDays = $TimeSpan.Days

            $Test.ValidationPasses = @($ValidationPasses)
            $Test.ValidationWarns = @($ValidationWarns)
            $Test.ValidationFails = @($ValidationFails)

            # Return test
            $Test
        }

        catch { Write-Verbose $_.Exception.Message }
    }

    # Aggregate validation results
    foreach ($Test in $CertificateTests.Tests) {
        $ValidationPassCount = ($Test.ValidationPasses | Measure-Object).Count
        $ValidationWarnCount = ($Test.ValidationWarns | Measure-Object).Count
        $ValidationFailCount = ($Test.ValidationFails | Measure-Object).Count

        if ($ValidationFailCount -gt 0) {
            $CertificateTests.ValidationFails.Add(('{0} - Failure on {1} check(s)' -f $Test.Hostname, $ValidationFailCount)) | Out-Null
        }

        if ($ValidationWarnCount -gt 0) {
            $CertificateTests.ValidationWarns.Add(('{0} - Warning on {1} check(s)' -f $Test.Hostname, $ValidationWarnCount)) | Out-Null
        }

        if ($ValidationPassCount -gt 0) {
            $CertificateTests.ValidationPasses.Add(('{0} - Pass on {1} check(s)' -f $Test.Hostname, $ValidationPassCount)) | Out-Null
        }
    }

    # Return tests
    $CertificateTests
}
