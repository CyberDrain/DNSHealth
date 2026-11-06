---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-MXRecord

## SYNOPSIS
Reads MX records for domain

## SYNTAX

```
Read-MXRecord [-Domain] <String> [<CommonParameters>]
```

## DESCRIPTION
Queries DNS servers to get MX records and returns in PSCustomObject list with Preference and Hostname.
LookupFailed is true when the resolver gave no usable answer (no response, SERVFAIL, REFUSED), so the
domain's MX records are unknown rather than missing.

## EXAMPLES

### EXAMPLE 1
```
Read-MXRecord -Domain gmail.com
```

Preference Hostname
---------- --------
   5 gmail-smtp-in.l.google.com.
  10 alt1.gmail-smtp-in.l.google.com.
  20 alt2.gmail-smtp-in.l.google.com.
  30 alt3.gmail-smtp-in.l.google.com.
  40 alt4.gmail-smtp-in.l.google.com.

## PARAMETERS

### -Domain
Domain to query

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
