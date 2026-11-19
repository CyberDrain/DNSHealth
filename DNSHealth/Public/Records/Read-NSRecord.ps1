function Read-NSRecord {
    <#
    .SYNOPSIS
    Reads NS records for domain

    .DESCRIPTION
    Queries DNS servers to get NS records and returns in PSCustomObject list

    .PARAMETER Domain
    Domain to query

    .EXAMPLE
    PS> Read-NSRecord -Domain gmail.com

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )
    $NSResults = [PSCustomObject]@{
        Domain           = ''
        Records          = [System.Collections.Generic.List[string]]::new()
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
        NameProvider     = ''
        IsSubdomain      = $false
        ParentDomain     = ''
    }
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    $DnsQuery = @{
        RecordType = 'ns'
        Domain     = $Domain
    }

    $NSResults.Domain = $Domain

    try {
        $Result = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop
    }

    catch { $Result = $null }

    # A name inside a parent zone has no NS records of its own; the authority section names that zone,
    # whose nameservers serve it.
    $Zone = "$(@($Result.Authority | Where-Object { $_.type -eq 6 })[0].name)".TrimEnd('.')
    if ($Result.Status -eq 0 -and -not $Result.Answer -and $Zone -and $Zone -ne $Domain.TrimEnd('.')) {
        try {
            $ZoneResult = Resolve-DnsHttpsQuery -RecordType 'ns' -Domain $Zone -ErrorAction Stop
            if ($ZoneResult.Status -eq 0 -and $ZoneResult.Answer) {
                $Result = $ZoneResult
                $NSResults.IsSubdomain = $true
                $NSResults.ParentDomain = $Zone
            }
        } catch {}
    }

    if ($Result.Status -eq 2 -and $Result.AD -eq $false) {
        $ValidationFails.Add('DNSSEC Validation failed.') | Out-Null
    }

    elseif ($Result.Status -ne 0 -or -not ($Result.Answer)) {
        $ValidationFails.Add('No nameservers found for this domain.') | Out-Null
        $NSRecords = $null
    }

    else {
        $NSRecords = $Result.Answer.data
        if ($NSResults.IsSubdomain) {
            $ValidationPasses.Add("This is a subdomain of $($NSResults.ParentDomain) and is served by its nameservers.") | Out-Null
        } else {
            $ValidationPasses.Add('Nameserver record is present.') | Out-Null
        }
        $NSResults.Records = @($NSRecords)
    }
    $NSResults.ValidationPasses = $ValidationPasses
    $NSResults.ValidationFails = $ValidationFails
    $NSResults
}
