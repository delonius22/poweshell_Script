function Decrypt-FileContent {
    param (
        [Parameter(Mandatory=$true)]
        [byte[]]$EncryptedData,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )
    
    # Convert key to bytes and hash it to get the right size
    $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $SHA256 = New-Object System.Security.Cryptography.SHA256Managed
    $KeyHash = $SHA256.ComputeHash($KeyBytes)
    
    # Create AES decryption object
    $AES = New-Object System.Security.Cryptography.AesManaged
    $AES.Key = $KeyHash
    
    # Extract the IV from the beginning of the file
    # AES IV is always 16 bytes
    $IV = $EncryptedData[0..15]
    $AES.IV = $IV
    
    # The rest is our encrypted content
    $EncryptedContent = $EncryptedData[16..$EncryptedData.Length]
    
    # Decrypt the content
    $Decryptor = $AES.CreateDecryptor()
    $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedContent, 0, $EncryptedContent.Length)
    
    # Convert back to string
    $DecryptedContent = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
    
    # Clean up
    $AES.Dispose()
    
    return $DecryptedContent
}

# Read and decrypt the file
$Key = gc env:computername   # Must match encryption key
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$FilePath = Join-Path $DesktopPath "test.dll.txt"

# Read the encrypted file
$EncryptedData = [System.IO.File]::ReadAllBytes($FilePath)

# Decrypt the content
$DecryptedContent = Decrypt-FileContent -EncryptedData $EncryptedData -Key $Key

Write-Host "Decrypted content: $DecryptedContent"