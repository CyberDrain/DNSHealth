# Use this file to override the default parameter values used by the `Build-Module`
# command when building the module (see `Get-Help Build-Module -Full` for details).
@{
    ModuleManifest           = 'DNSHealth\DNSHealth.psd1'
    # Subsequent relative paths are to the ModuleManifest
    OutputDirectory          = '..\Output\'
    VersionedOutputDirectory = $false
    # SevenTinyRsa.dll is the precompiled [SevenTiny.Bantina.Security.RSACommon]
    # helper used by Get-RsaPublicKeyInfo. Bundling it lets DNSHealth.psd1's
    # RequiredAssemblies preload the type so the inline Add-Type fallback
    # short-circuits — required on hosts where runtime CSharp compilation
    # fails (no $PSHOME/ref). Source: Source/SevenTinyRsa/. CopyDirectories
    # is ModuleBuilder's alias for CopyPaths, which accepts files too.
    CopyDirectories          = @('MailProviders', 'SevenTinyRsa.dll', 'CertificateCheck.dll')
}