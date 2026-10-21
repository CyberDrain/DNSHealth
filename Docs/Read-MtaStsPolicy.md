---
external help file: DNSHealth-help.xml
Module Name: DNSHealth
online version:
schema: 2.0.0
---

# Read-MtaStsPolicy

## SYNOPSIS
Resolve and validate MTA-STS policy

## SYNTAX

```
Read-MtaStsPolicy [-Domain] <String> [[-TimeoutSec] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
Retrieve mta-sts.txt from .well-known directory on domain

## EXAMPLES

### EXAMPLE 1
```
Read-MtaStsPolicy -Domain gmail.com
```

## PARAMETERS

### -Domain
Domain to process MTA-STS policy

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

### -TimeoutSec
Seconds to wait for the policy file. Defaults to 10

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 10
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
