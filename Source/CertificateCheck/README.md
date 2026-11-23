# CertificateCheck

Precompiled `[DNSHealth.CertificateCheck]`, used by
`Private/Get-ServerCertificateValidation.ps1` (and so `Test-HttpsCertificate` and `Test-MtaSts`).
It is preloaded through `DNSHealth.psd1`'s `RequiredAssemblies`, the same way as
[SevenTinyRsa](../SevenTinyRsa/README.md), so the module works in hosts that cannot compile C# at runtime.
The inline `Add-Type` source in `Get-ServerCertificateValidation.ps1` stays as the fallback; keep the two in sync.

## Rebuild

```pwsh
cd Source/CertificateCheck
dotnet build CertificateCheck.csproj -c Release -o ../../DNSHealth/
```
