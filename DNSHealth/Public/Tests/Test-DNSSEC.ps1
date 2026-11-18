function Test-DNSSEC {
    <#
    .SYNOPSIS
    Test Domain for DNSSEC validation

    .DESCRIPTION
    Requests dnskey record from DNS and checks response validation (AD=True)

    .PARAMETER Domain
    Domain to check

    .EXAMPLE
    PS> Test-DNSSEC -Domain example.com

    Domain           : example.com
    ValidationPasses : {example.com - DNSSEC enabled and validated}
    ValidationFails  : {}
    Keys             : {...}

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )
    $DSResults = [PSCustomObject]@{
        Domain           = $Domain
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
        Keys             = [System.Collections.Generic.List[string]]::new()
    }
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    $DnsQuery = @{
        RecordType = 'dnskey'
        Domain     = $Domain
    }

    $Result = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop
    if ($Result.Status -eq 2 -and $Result.AD -eq $false) {
        $ValidationFails.Add('DNSSEC Validation failed.') | Out-Null
    }

    else {
        $RecordCount = ($Result.Answer.data | Measure-Object).Count
        if ($null -eq $Result) {
            $ValidationFails.Add('DNSSEC is not set up for this domain.') | Out-Null
        }

        else {
            if ($Result.Status -eq 3) {
                $ValidationFails.Add('DNSSEC is not set up for this domain.') | Out-Null
            }

            elseif ($RecordCount -gt 0) {
                if ($Result.AD -eq $false) {
                    $ValidationFails.Add('DNSSEC is enabled, but the DNS query response was not validated. Ensure DNSSEC has been enabled on your domain provider.') | Out-Null
                }

                else {
                    $ValidationPasses.Add('DNSSEC is enabled and validated for this domain.') | Out-Null
                }
                $DSResults.Keys = $Result.answer.data
            }

            # No keys at this name but an authenticated answer: the name sits inside a signed zone (keys live at its apex).
            elseif ($Result.AD -eq $true) {
                $Zone = "$(@($Result.Authority)[0].name)".TrimEnd('.')
                $ValidationPasses.Add("DNSSEC is enabled and validated for this domain through the signed zone $(if ($Zone) { $Zone } else { 'above it' }).") | Out-Null
            }

            else {
                $ValidationFails.Add('DNSSEC is not set up for this domain.') | Out-Null
            }
        }
    }

    $DSResults.ValidationPasses = $ValidationPasses
    $DSResults.ValidationFails = $ValidationFails
    $DSResults
}
