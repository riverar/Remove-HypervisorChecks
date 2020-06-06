[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateScript({ Test-Path $_ })]
    [string]
    $DriverPath,
    [Parameter(Mandatory=$true, ParameterSetName='Nvidia')]
    [switch]
    $Nvidia,
    [Parameter(Mandatory=$true, ParameterSetName='Amd')]
    [switch]
    $Amd
)

function Get-BinaryWriter {
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $FilePath
    )

    return New-Object IO.BinaryWriter -ArgumentList @(
        New-Object IO.FileStream -ArgumentList @(
            $FilePath,
            "Open",
            "Write",
            "None"
        )
    )
}

function Find-BytePattern {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $FilePath,
        [Parameter(Mandatory=$true)]
        [string]
        $Pattern
    )

    $FileStream = New-Object IO.FileStream -ArgumentList @(
        (Resolve-Path $FilePath),
        "Open",
        "Read",
        "None"
    )

    $StreamReader = New-Object IO.StreamReader -ArgumentList @(
        $FileStream,
        [Text.Encoding]::GetEncoding("iso-8859-1")
    )

    $Bytes = $StreamReader.ReadToEnd()
    $StreamReader.Close()
    $StreamReader.Dispose()
    
    $Regex = [Regex]($Pattern.Insert(0, "\x") -replace ' ', '\x')
    return $Regex.Matches($Bytes)
}

$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"

Write-Output ""
Write-Output "Remove-HypervisorChecks"
Write-Output "Copyright(c) 2020 Rafael Rivera"
Write-Output "https://withinrafael.com"
Write-Output ""

if($Amd) {
    Write-Error "[!] AMD GPUs are not yet supported."
}

if(Test-Path "Tools") {
    Remove-Item "Tools" -Recurse -Force
}

New-Item -ItemType Directory "Tools" | Out-Null
$TempPath = (New-Item -ItemType Directory "Tools\Temp").FullName
$7ZipInstallPath = (New-Item -ItemType Directory "Tools\Temp\7zip").FullName
$7ZipMsiPath = Join-Path -Path $TempPath -ChildPath "7z.msi"
$7ZipPath = Join-Path -Path $7ZipInstallPath -ChildPath "Files\7-Zip\7z.exe"

Write-Output "[+] Staging 7-Zip..."
Invoke-WebRequest -UseBasicParsing "https://www.7-zip.org/a/7z1900-x64.msi" -OutFile $7ZipMsiPath
Start-Process -FilePath msiexec.exe -Wait -ArgumentList @(
    "/passive",    
    "/a",
    "`"$7ZipMsiPath`"",
    "TARGETDIR=`"$7ZipInstallPath`""
)

Write-Output "[+] Extracting $DriverPath..."
$DriverPath = Resolve-Path $DriverPath
$ExtractedDriverPath = Join-Path -Path $TempPath -ChildPath "Extracted"
Start-Process -FilePath $7ZipPath -Wait -ArgumentList @(
    "x",
    "-i!*",
    "`"$DriverPath`"",
    "-o`"$ExtractedDriverPath`""
)

if($Nvidia) {
    $DriverPath = Join-Path -Path $ExtractedDriverPath -ChildPath "Display.Driver"
    $DriverCatPath = Join-Path -Path $DriverPath -ChildPath "nv_disp.cat"
    $CompressedKernelDriverPath = Join-Path -Path $DriverPath -ChildPath "nvlddmkm.sy_"
    $KernelDriverPath = Join-Path -Path $DriverPath -ChildPath "nvlddmkm.sys"
    
    Write-Output "[+] Expanding $CompressedKernelDriverPath..."
    Start-Process -FilePath expand.exe -Wait -ArgumentList @(
        "`"$CompressedKernelDriverPath`"",
        "`"$KernelDriverPath`""
    )

    Write-Output "[+] Looking for target byte pattern..."
    $Matches = Find-BytePattern -FilePath $KernelDriverPath -Pattern 'E8 A8 FD FF FF 85 C0 75 6C'
    if($Matches.Count -ne 1) {
        Write-Error "[!] Offset found $($Matches.Count) times."
    }
    Write-Output "[+] Found @ $($Matches.Index)."

    Write-Output "[+] Patching $KernelDriverPath..."
    $Writer = Get-BinaryWriter -FilePath $KernelDriverPath
    $Writer.Seek($Matches[0].Index, 'Begin') | Out-Null
    $Writer.Write([byte[]]@(
        0x48, 0x31, 0xC0, # // xor rax, rax
        0xEB, 0x02,       # // jmp short $+2
        0x85, 0xC0,       # // test eax, eax
        0xEB              # // jmp [...]
    ))
    $Writer.Close()
    $Writer.Dispose()
    Write-Output "[+] Patched."

    Write-Output "[+] Compressing $KernelDriverPath..."
    Start-Process -FilePath makecab.exe -Wait -ArgumentList @(
        "`"$KernelDriverPath`"",
        "`"$CompressedKernelDriverPath`""
    )
    Remove-Item $KernelDriverPath

    Write-Output "[+] Rebuilding driver package (this will take a few minutes)..."
    Start-Process -FilePath inf2cat.exe -Wait -ArgumentList @(
        "/os:10_X64",
        "/v",
        "`"/driver:$DriverPath`""
    )

    Write-Output "[+] Signing catalog..."
    $Certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=Auto-generated Self Signed Certificate" `
        -CertStoreLocation "Cert:\CurrentUser\My"

    Start-Process -FilePath signtool.exe -Wait -ArgumentList @(
        "sign",
        "/sha1 $($Certificate.Thumbprint)",
        "`"$DriverCatPath`""
    )

    Remove-Item $Certificate.PSPath

} else {
    $KernelDriverPath = (Join-Path -Path $ExtractedDriverPath -ChildPath "Packages\Drivers\Display\*\*\atikmdag.sys" | Resolve-Path)
    $DriverPath = $KernelDriverPath | Split-Path
    
    # Incomplete
}

Write-Output "[+] Packaging driver..."
    Start-Process -FilePath $7ZipPath -Wait -ArgumentList @(
        "a",
        "-r",
        "patched-driver.zip",
        "`"$ExtractedDriverPath\*`""
    )

Write-Output "[+] Done."
Write-Output ""