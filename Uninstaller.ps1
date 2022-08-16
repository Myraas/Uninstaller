# List Apps to uninstall here.
$apps = @(
    "*Adobe*"
)

# List Apps to prevent uninstallation here.
$whitelist = @(
    "PhotoShop"
    "Illustrator"
    "Creative"
    "Lightroom"
    "Premiere"
    "Effects"
    "Substance"
    "Stock"
    "Express"
    "Dreamweaver"
    "Stager"
    "Sampler"
    "Painter"
    "Designer"
    "InCopy"
    "Rush"
    "Aero"
    "Express"
    "Audition"
) -Join "|"

# - DO NOT EDIT BELOW THIS LINE - 
# --------------------------------------------------------------------------------------

Clear-Host

Start-Transcript -Path "C:\temp\Uninstaller-Transcript.txt"
[System.DateTime]::Now

#Check if C:\temp Exists and Create Directory
if (!(Test-Path -Path C:\temp)){mkdir C:\temp}

# Log actions in the C:\temp directory
$Timestamp = Get-Date -Format "yyyy-MM-dd_THHmmss"
$LogFile = "C:\temp\Uninstaller-MsiexecLog_$Timestamp.log"

# Whitelist Regex
$whitelistRegex=[Regex]::New($whitelist,[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Get-InstalledApps{
    if ([IntPtr]::Size -eq 4) {
        $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        $regpath = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    Get-ItemProperty $regpath | .{process{if($_.DisplayName -and $_.UninstallString) { $_ } }}
}

$MSIUninstallArguments = @(
    "/X"
    "$($result.PSChildName)"
    "REBOOT=ReallySuppress"
    "/qn"
    "/Q"
    "/L*V"
    "$LogFile"
)

 Get-Process * | Where-Object {$_.CompanyName -like $app -or $_.Path -like $app} | Stop-Process

foreach ($app in $apps){
    $results = ( Get-InstalledApps | Where-Object { ($_.DisplayName -like $app) -and ($_.DisplayName -notmatch $whitelistRegex) } ) | Sort-Object

    foreach($result in $results){
        Write-Host $result `
        
       Start-Process "C:\Windows\System32\Msiexec.exe" -ArgumentList $MSIUninstallArguments -Wait -NoNewWindow
       Get-WmiObject -Class Win32_Product | Where-Object { ($_.Name -like $app) -and ($_.Name -notmatch $whitelistRegex) } | foreach-object -process {$_.Uninstall()}
    }
}

# Check if Previous Adobe Installers Exist in C:\temp and Delete
if ((Test-Path -Path C:\temp\Adobe.zip)){Remove-Item C:\temp\Adobe.zip}
if ((Test-Path -Path C:\temp\AdobeAcrobatReader.exe)){Remove-Item C:\temp\AdobeAcrobatReader.exe}

# Download Adobe Acrobat to C:\temp
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$sourceURL = "------URL TO ZIP INSTALLER HERE------"
Invoke-WebRequest -Uri $sourceURL -OutFile "C:\temp\Adobe.zip"

# Throw Error if download fails
if ((Get-Item -Path C:\temp\Adobe.zip).length/1KB -le 114){Write-Host "Error Downloading File." -ForegroundColor Red}

# Unzip Archive
Expand-Archive "C:\temp\Adobe.zip" -DestinationPath "C:\temp"

# Silent Install Adobe Acrobat EXE
C:\temp\AdobeAcrobatReader.exe /sAll /rs /msi EULA_ACCEPT=YES

Write-Host ""

Stop-Transcript
