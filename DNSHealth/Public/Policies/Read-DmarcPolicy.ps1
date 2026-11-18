function Read-DmarcPolicy {
    <#
    .SYNOPSIS
    Resolve and validate DMARC policy

    .DESCRIPTION
    Query domain for DMARC policy (_dmarc.domain.com) and parse results. Record is checked for issues.

    .PARAMETER Domain
    Domain to process DMARC policy

    .EXAMPLE
    PS> Read-DmarcPolicy -Domain gmail.com

    Domain           : gmail.com
    Record           : v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com
    Version          : DMARC1
    Policy           : none
    SubdomainPolicy  : quarantine
    Percent          : 100
    DkimAlignment    : r
    SpfAlignment     : r
    ReportFormat     : afrf
    ReportInterval   : 86400
    ReportingEmails  : {mailauth-reports@google.com}
    ForensicEmails   : {}
    FailureReport    : 0
    ValidationPasses : {Aggregate reports are being sent}
    ValidationWarns  : {Policy is not being enforced, Subdomain policy is only partially enforced with quarantine, Failure report option 0 will only generate a report on both SPF and DKIM misalignment. It is recommended to set this value to 1}
    ValidationFails  : {}

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # Initialize object
    $DmarcAnalysis = [PSCustomObject]@{
        Domain           = $Domain
        Record           = ''
        Version          = ''
        Policy           = ''
        SubdomainPolicy  = ''
        InheritedFrom    = ''
        Percent          = 100
        DkimAlignment    = 'r'
        SpfAlignment     = 'r'
        ReportFormat     = 'afrf'
        ReportInterval   = 86400
        ReportingEmails  = [System.Collections.Generic.List[string]]::new()
        ForensicEmails   = [System.Collections.Generic.List[string]]::new()
        FailureReport    = ''
        ValidationPasses = [System.Collections.Generic.List[string]]::new()
        ValidationWarns  = [System.Collections.Generic.List[string]]::new()
        ValidationFails  = [System.Collections.Generic.List[string]]::new()
    }

    # Validation lists
    $ValidationPasses = [System.Collections.Generic.List[string]]::new()
    $ValidationWarns = [System.Collections.Generic.List[string]]::new()
    $ValidationFails = [System.Collections.Generic.List[string]]::new()

    # Email report domains
    $ReportDomains = [System.Collections.Generic.List[string]]::new()

    # Validation ranges
    $PolicyValues = @('none', 'quarantine', 'reject')
    $FailureReportValues = @('0', '1', 'd', 's')
    $ReportFormatValues = @('afrf')

    $RecordCount = 0

    $DnsQuery = @{
        RecordType = 'TXT'
        Domain     = "_dmarc.$Domain"
    }

    # Resolve DMARC record

    $Query = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop

    $RecordCount = 0
    $Query.Answer | Where-Object { $_.data -match '^v=DMARC1' } | ForEach-Object {
        $DmarcRecord = $_.data
        $DmarcAnalysis.Record = $DmarcRecord
        $RecordCount++
    }

    # A subdomain without its own record is covered by the nearest parent's subdomain policy (RFC 7489 6.6.3).
    $PolicyDomain = $Domain
    if ($RecordCount -eq 0 -and $Query.Status -in 0, 3) {
        $Labels = $Domain.Split('.')
        for ($i = 1; $i -le $Labels.Count - 2; $i++) {
            $Parent = $Labels[$i..($Labels.Count - 1)] -join '.'
            $ParentQuery = Resolve-DnsHttpsQuery -RecordType 'TXT' -Domain "_dmarc.$Parent" -ErrorAction Stop
            $ParentRecords = @($ParentQuery.Answer | Where-Object { $_.data -match '^v=DMARC1' })
            if ($ParentRecords.Count -gt 0) {
                $Query = $ParentQuery
                $PolicyDomain = $Parent
                $DmarcAnalysis.InheritedFrom = $Parent
                foreach ($ParentRecord in $ParentRecords) {
                    $DmarcRecord = $ParentRecord.data
                    $DmarcAnalysis.Record = $DmarcRecord
                    $RecordCount++
                }
                $ValidationPasses.Add("This domain has no DMARC record of its own, so the subdomain policy of $Parent applies.") | Out-Null
                break
            }
        }
    }

    if ($Query.Status -eq 2 -and $Query.AD -eq $false) {
        $ValidationFails.Add('DNSSEC validation failed.') | Out-Null
    }

    elseif ($Query.Status -ne 0 -or $RecordCount -eq 0) {
        $ValidationFails.Add('This domain does not have a DMARC record.') | Out-Null
    }

    elseif (($Query.Answer | Measure-Object).Count -eq 1 -and $RecordCount -eq 0) {
        $ValidationFails.Add("The record must begin with 'v=DMARC1'.") | Out-Null
    }

    elseif ($RecordCount -gt 1) {
        $ValidationFails.Add('This domain has multiple records. The policy evaluation will fail.') | Out-Null
    }

    # Split DMARC record into name/value pairs
    $TagList = [System.Collections.Generic.List[object]]::new()
    Foreach ($Element in ($DmarcRecord -split ';').trim()) {
        $Name, $Value = $Element -split '='
        $TagList.Add(
            [PSCustomObject]@{
                Name  = $Name
                Value = $Value
            }
        ) | Out-Null
    }

    # Loop through name/value pairs and set object properties
    $x = 0
    foreach ($Tag in $TagList) {
        switch ($Tag.Name) {
            'v' {
                # REQUIRED: Version
                $DmarcAnalysis.Version = $Tag.Value
            }
            'p' {
                # REQUIRED: Policy
                $DmarcAnalysis.Policy = $Tag.Value
            }
            'sp' {
                # Subdomain policy, defaults to policy record
                $DmarcAnalysis.SubdomainPolicy = $Tag.Value
            }
            'rua' {
                # Aggregate report emails
                $ReportingEmails = $Tag.Value -split ', '
                $ReportEmailsSet = $false
                foreach ($MailTo in $ReportingEmails) {
                    if ($MailTo -notmatch '^mailto:') { $ValidationFails.Add("Aggregate report email addresses must begin with 'mailto:', multiple addresses must be separated by commas.") | Out-Null }
                    else {
                        $ReportEmailsSet = $true
                        if ($MailTo -match '^mailto:(?<Email>.+@(?<Domain>[^!]+?))(?:!(?<SizeLimit>[0-9]+[kmgt]?))?$') {
                            if ($ReportDomains -notcontains $Matches.Domain -and $Matches.Domain -ne $PolicyDomain) {
                                $ReportDomains.Add($Matches.Domain) | Out-Null
                            }
                            $DmarcAnalysis.ReportingEmails.Add($Matches.Email) | Out-Null
                        }
                    }
                }
                if (!$DmarcAnalysis.ReportingEmails) { $DmarcAnalysis.ReportingEmails.Add($null) }
                if ($ReportEmailsSet) {
                    $ValidationPasses.Add('Aggregate reports are being sent.') | Out-Null
                }

                else {
                    $ValidationWarns.Add('Aggregate reports are not being sent.') | Out-Null
                }
            }
            'ruf' {
                # Forensic reporting emails
                foreach ($MailTo in ($Tag.Value -split ', ')) {
                    if ($MailTo -notmatch '^mailto:') { $ValidationFails.Add("Forensic report email must begin with 'mailto:', multiple addresses must be separated by commas - found $($Tag.Value)") | Out-Null }
                    else {
                        if ($MailTo -match '^mailto:(?<Email>.+@(?<Domain>[^!]+?))(?:!(?<SizeLimit>[0-9]+[kmgt]?))?$') {
                            if ($ReportDomains -notcontains $Matches.Domain -and $Matches.Domain -ne $PolicyDomain) {
                                $ReportDomains.Add($Matches.Domain) | Out-Null
                            }
                            $DmarcAnalysis.ForensicEmails.Add($Matches.Email) | Out-Null
                        }
                    }
                }
            }
            'fo' {
                # Failure reporting options
                $DmarcAnalysis.FailureReport = $Tag.Value
            }
            'pct' {
                # Percentage of email to check
                $DmarcAnalysis.Percent = [int]$Tag.Value
            }
            'adkim' {
                # DKIM Alignmenet
                $DmarcAnalysis.DkimAlignment = $Tag.Value
            }
            'aspf' {
                # SPF Alignment
                $DmarcAnalysis.SpfAlignment = $Tag.Value
            }
            'rf' {
                # Report Format
                $DmarcAnalysis.ReportFormat = $Tag.Value
            }
            'ri' {
                # Report Interval
                $DmarcAnalysis.ReportInterval = $Tag.Value
            }
        }
        $x++
    }

    if ($RecordCount -gt 0) {
        # Check report domains for DMARC reporting record
        $ReportDomainCount = $ReportDomains | Measure-Object | Select-Object -ExpandProperty Count
        if ($ReportDomainCount -gt 0) {
            $ReportDomainsPass = $true
            foreach ($ReportDomain in $ReportDomains) {
                $ReportDomainQuery = "$PolicyDomain._report._dmarc.$ReportDomain"
                $DnsQuery['Domain'] = $ReportDomainQuery
                $ReportDmarcQuery = Resolve-DnsHttpsQuery @DnsQuery -ErrorAction Stop
                $ReportDmarcRecord = $ReportDmarcQuery.Answer.data
                if ($null -eq $ReportDmarcQuery -or $ReportDmarcQuery.Status -ne 0) {
                    $ValidationWarns.Add("Report DMARC policy for $PolicyDomain is missing from $ReportDomain, reports will not be delivered. Expected record: '$PolicyDomain._report._dmarc.$ReportDomain' - Expected value: 'v=DMARC1;'") | Out-Null
                    $ReportDomainsPass = $false
                }

                elseif ($ReportDmarcRecord -notmatch '^v=DMARC1') {
                    $ValidationWarns.Add("Report DMARC policy for $PolicyDomain is missing from $ReportDomain, reports will not be delivered. Expected record: '$PolicyDomain._report._dmarc.$ReportDomain' - Expected value: 'v=DMARC1;'.") | Out-Null
                    $ReportDomainsPass = $false
                }
            }

            if ($ReportDomainsPass) {
                $ValidationPasses.Add('All external reporting domains allow this domain to send DMARC reports.') | Out-Null
            }

        }
        # Check for missing record tags and set defaults
        if ($DmarcAnalysis.Policy -eq '') { $ValidationFails.Add('The policy tag (p=) is missing from this record. Set this to none, quarantine or reject.') | Out-Null }
        if ($DmarcAnalysis.SubdomainPolicy -eq '') { $DmarcAnalysis.SubdomainPolicy = $DmarcAnalysis.Policy }
        # An inherited record applies its subdomain policy to this domain.
        if ($DmarcAnalysis.InheritedFrom) { $DmarcAnalysis.Policy = $DmarcAnalysis.SubdomainPolicy }

        # Check policy for errors and best practice
        if ($PolicyValues -notcontains $DmarcAnalysis.Policy) { $ValidationFails.Add("The policy must be one of the following: none, quarantine or reject. Found $($Tag.Value)") | Out-Null }
        if ($DmarcAnalysis.Policy -eq 'reject') { $ValidationPasses.Add('The domain policy is set to reject, this is best practice.') | Out-Null }
        if ($DmarcAnalysis.Policy -eq 'quarantine') { $ValidationWarns.Add('The domain policy is only partially enforced with quarantine. Set this to reject to be fully compliant.') | Out-Null }
        if ($DmarcAnalysis.Policy -eq 'none') { $ValidationFails.Add('The domain policy is not being enforced.') | Out-Null }

        # Check subdomain policy
        if ($PolicyValues -notcontains $DmarcAnalysis.SubdomainPolicy) { $ValidationFails.Add("The subdomain policy must be one of the following: none, quarantine or reject. Found $($DmarcAnalysis.SubdomainPolicy)") | Out-Null }
        if ($DmarcAnalysis.SubdomainPolicy -eq 'reject') { $ValidationPasses.Add('The subdomain policy is set to reject, this is best practice.') | Out-Null }
        if ($DmarcAnalysis.SubdomainPolicy -eq 'quarantine') { $ValidationWarns.Add('The subdomain policy is only partially enforced with quarantine. Set this to reject to be fully compliant.') | Out-Null }
        if ($DmarcAnalysis.SubdomainPolicy -eq 'none') { $ValidationFails.Add('The subdomain policy is not being enforced.') | Out-Null }

        # Check percentage - validate range and ensure 100%
        if ($DmarcAnalysis.Percent -lt 100 -and $DmarcAnalysis.Percent -ge 0) { $ValidationWarns.Add('Not all emails will be processed by the DMARC policy.') | Out-Null }
        if ($DmarcAnalysis.Percent -gt 100 -or $DmarcAnalysis.Percent -lt 0) { $ValidationFails.Add('The percentage tag (pct=) must be between 0 and 100.') | Out-Null }

        # Check report format
        if ($ReportFormatValues -notcontains $DmarcAnalysis.ReportFormat) { $ValidationFails.Add("The report format '$($DmarcAnalysis.ReportFormat)' is not supported.") | Out-Null }

        # Check forensic reports and failure options
        $ForensicCount = ($DmarcAnalysis.ForensicEmails | Measure-Object | Select-Object -ExpandProperty Count)
        if ($ForensicCount -eq 0 -and $DmarcAnalysis.FailureReport -ne '') { $ValidationWarns.Add('Forensic email reports recipients are not defined and failure report options are set. No reports will be sent. This is not an issue unless you are expecting forensic reports.') | Out-Null }
        if ($DmarcAnalysis.FailureReport -eq '' -and $null -ne $DmarcRecord) { $DmarcAnalysis.FailureReport = '0' }
        if ($ForensicCount -gt 0) {
            $ReportOptions = $DmarcAnalysis.FailureReport -split ':'
            foreach ($ReportOption in $ReportOptions) {
                if ($FailureReportValues -notcontains $ReportOption) { $ValidationFails.Add("Failure report option '$ReportOption' is not a valid choice.") | Out-Null }
                if ($ReportOption -eq '1') { $ValidationPasses.Add('Failure report option 1 generates forensic reports on SPF or DKIM misalignment.') | Out-Null }
                if ($ReportOption -eq '0' -and $ReportOptions -notcontains '1') { $ValidationWarns.Add('Failure report option 0 will only generate a forensic report on both SPF and DKIM misalignment. It is recommended to set this value to 1.') | Out-Null }
                if ($ReportOption -eq 'd' -and $ReportOptions -notcontains '1') { $ValidationWarns.Add('Failure report option d will only generate a forensic report on failed DKIM evaluation. It is recommended to set this value to 1.') | Out-Null }
                if ($ReportOption -eq 's' -and $ReportOptions -notcontains '1') { $ValidationWarns.Add('Failure report option s will only generate a forensic report on failed SPF evaluation. It is recommended to set this value to 1.') | Out-Null }
            }
        }
    }

    # Add the validation lists
    $DmarcAnalysis.ValidationPasses = @($ValidationPasses)
    $DmarcAnalysis.ValidationWarns = @($ValidationWarns)
    $DmarcAnalysis.ValidationFails = @($ValidationFails)

    # Return DMARC analysis
    $DmarcAnalysis
}
