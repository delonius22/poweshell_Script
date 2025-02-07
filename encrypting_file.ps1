function Encrypt-FileContent {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Content,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )
    
    # Convert the content and key to bytes
    $ContentBytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    
    # Create AES encryption object with proper key size
    $AES = New-Object System.Security.Cryptography.AesManaged
    # Ensure the key is the right size by hashing it
    $SHA256 = New-Object System.Security.Cryptography.SHA256Managed
    $AES.Key = $SHA256.ComputeHash($KeyBytes)
    $AES.GenerateIV()
    
    # Create the encryptor and encrypt the content
    $Encryptor = $AES.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($ContentBytes, 0, $ContentBytes.Length)
    
    # Combine the Initialization Vector with the encrypted content
    # We need the IV for later decryption
    $FullData = $AES.IV + $EncryptedBytes
    
    # Clean up
    $AES.Dispose()
    
    return $FullData
}

# The main script execution starts here
$Key = gc env:computername  # Your encryption key
$Message = "Youve been pwned!"  # The message to encrypt

# Encrypt the message using our function
$EncryptedContent = Encrypt-FileContent -Content $Message -Key $Key

# Save to desktop
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$FilePath = Join-Path $DesktopPath "test.dll.txt"
[System.IO.File]::WriteAllBytes($FilePath, $EncryptedContent)

Write-Host "File has been encrypted and saved to: $FilePath"