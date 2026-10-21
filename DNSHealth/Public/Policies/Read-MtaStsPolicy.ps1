function Read-MtaStsPolicy {
    <#
    .SYNOPSIS
    Resolve and validate MTA-STS policy

    .DESCRIPTION
    Retrieve mta-sts.txt from .well-known directory on domain

    .PARAMETER Domain
    Domain to process MTA-STS policy

    .PARAMETER TimeoutSec
    Seconds to wait for the policy file. Defaults to 10

    .EXAMPLE
    PS> Read-MtaStsPolicy -Domain gmail.com
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter()]
        [int]$TimeoutSec = 10
    )

    $StsPolicyAnalysis = [PSCustomObject]@{
        Domain           = $Domain
        Version          = ''
        Mode             = ''
        Mx               = [System.Collections.Generic.List[string]]::new()
        MaxAge           = ''
        Exists           = $false
        IsValid          = $false
        HasWarnings      = $false
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
    }

    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    # Valid policy modes
    $StsPolicyModes = @('testing', 'enforce')

    # Request policy file from domain, only accept text/plain results
    $RequestParams = @{
        Uri        = ('https://mta-sts.{0}/.well-known/mta-sts.txt' -f $Domain)
        TimeoutSec = $TimeoutSec
        Headers    = @{
            Accept = 'text/plain'
        }
    }

    $PolicyExists = $false
    try {
        $wr = Invoke-WebRequest @RequestParams -ErrorAction Stop
        $PolicyExists = $true
        $StsPolicyAnalysis.Exists = $true
    }

    catch [System.Threading.Tasks.TaskCanceledException], [System.TimeoutException] {
        $ValidationFails.Add(('MTA-STS policy for {0} did not respond within {1} seconds' -f $Domain, $TimeoutSec)) | Out-Null
    }

    catch {
        $ValidationFails.Add(('MTA-STS policy does not exist for {0}' -f $Domain)) | Out-Null
    }

    # Policy file is key value pairs split on new lines
    $StsPolicyEntries = [System.Collections.Generic.List[object]]::new()
    $Entries = $wr.Content -split "`r?`n"
    foreach ($Entry in $Entries) {
        if ($null -ne $Entry) {
            try {
                $Name, $Value = $Entry -split ':'
                $StsPolicyEntries.Add(
                    [PSCustomObject]@{
                        Name  = $Name.trim()
                        Value = $Value.trim()
                    }
                ) | Out-Null
            }

            catch { Write-Verbose $_.Exception.Message }
        }
    }

    foreach ($StsPolicyEntry in $StsPolicyEntries) {
        switch ($StsPolicyEntry.Name) {
            'version' {
                # REQUIRED: Version
                $StsPolicyAnalysis.Version = $StsPolicyEntry.Value
            }
            'mode' {
                $StsPolicyAnalysis.Mode = $StsPolicyEntry.Value
            }
            'mx' {
                $StsPolicyAnalysis.Mx.Add($StsPolicyEntry.Value) | Out-Null
            }
            'max_age' {
                $StsPolicyAnalysis.MaxAge = $StsPolicyEntry.Value
            }
        }
    }

    # Check policy for issues
    if ($PolicyExists) {
        if ($StsPolicyAnalysis.Version -ne 'STSv1') {
            $ValidationFails.Add("Version must be STSv1 - found $($StsPolicyEntry.Value)") | Out-Null
        }
        if ($StsPolicyAnalysis.Version -eq '') {
            $ValidationFails.Add('Version is missing from policy') | Out-Null
        }
        if ($StsPolicyModes -notcontains $StsPolicyAnalysis.Mode) {
            $ValidationFails.Add(('Policy mode "{0}" is not valid. (Options: {1})' -f $StsPolicyAnalysis.Mode, $StsPolicyModes -join ', '))
        }
        if ($StsPolicyAnalysis.Mode -eq 'Testing') {
            $ValidationWarns.Add('MTA-STS policy is in testing mode, no action will be taken') | Out-Null
            $StsPolicyAnalysis.HasWarnings = $true
        }

        $ValidationFailCount = ($ValidationFails | Measure-Object).Count
        if ($ValidationFailCount -eq 0) {
            $ValidationPasses.Add('MTA-STS policy is valid')
            $StsPolicyAnalysis.IsValid = $true
        }
    }

    # Aggregate validation results
    $StsPolicyAnalysis.ValidationPasses = @($ValidationPasses)
    $StsPolicyAnalysis.ValidationWarns = @($ValidationWarns)
    $StsPolicyAnalysis.ValidationFails = @($ValidationFails)

    $StsPolicyAnalysis
}
