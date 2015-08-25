#Requires –Version 2
Function Split-Data
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0 )]
        [Object[]]$Array,
        
        [Parameter( Mandatory = $True, Position = 1 )]
        [int]$BlockSize
    )

    Foreach($i in (0..($PartCount = [Math]::Floor($Array.Length / $BlockSize)))) 
    { 
        ,($Array[($i*$BlockSize)..($BlockSize*($i+1)-1)]) 
    } 
}

Function Convert-HexToBytes
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0,
                    ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]$HexString
    )
    $HexString.ToLower() -split '([a-f0-9]{2})' | ? { $_ } | % { [Convert]::ToByte($_, 16) }
}

Function Convert-BytesToBase64
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0,
                    ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$Bytes
    )
    [Convert]::ToBase64String($Bytes)
}

Function Convert-Base64ToBytes
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0,
                    ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$Base64
    )
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Base64))
}


Function Get-FixedXOR
{
    Param (
        [Parameter( Mandatory = $True, Position = 0 )]
        [Byte]$XOR1,

        [Parameter( Mandatory = $True, Position = 1 )]
        [Byte]$XOR2
    )
    $XOR1 -bxor $XOR2
}

Function Get-BruteXOR
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0 )]
        [Byte[]]$Bytes,

        [Parameter( Mandatory = $True, Position = 1 )]
        [int[]]$Keys
    )
    $Scores = @()
    Foreach ($Key in $Keys)
    {
        $Decrypted = ''
        $Failed = $false
        $Bytes | % { 
            $DecryptedValue = Get-FixedXOR $_  $Key
            if (($DecryptedValue -lt 32 -or $DecryptedValue -gt 126) -and 
                 $DecryptedValue -ne 10 -and $DecryptedValue -ne 13)
            {
               $Failed = $True; continue
            }
            $Decrypted += [char]$DecryptedValue
        }
        if (-not $Failed) 
        { 
            $FrequencyScore = ($Decrypted | Select-String "[etaoinshrdlu ]" -AllMatches | % { $_.Matches } | % { $_.Value }).Length
            $Scores += New-Object PSObject -Property @{
                            'KeyValue'  = $Key
                            'Key'       = [char]$Key
                            'Decrypted' = $Decrypted
                            'Score'     = $FrequencyScore
                        }
        }
    }
    if ($Scores.Length -gt 0) { $Scores }
}

Function Invoke-RepeatingXOR
{
    [CmdletBinding( DefaultParameterSetName='Plain' )] 
    Param (
        [Parameter( ParameterSetName='Plain', Position = 0 )]
        [ValidateNotNullOrEmpty()]
        [String]$Plaintext,

        [Parameter( ParameterSetName='Hex', Position = 0 )]
        [ValidateNotNullOrEmpty()]
        [String]$HexString,
        
        [Parameter( Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$BinaryData,

        [Parameter( Mandatory=$True )]
        [ValidateNotNullOrEmpty()]
        [String]$KeyPhrase,

        [Parameter( Mandatory=$False )]
        [Switch]$AsString = $False
    )

    switch ($PsCmdlet.ParameterSetName)
    {
        "Plain" { $BinaryData = [Text.Encoding]::UTF8.GetBytes(($Plaintext -replace "`r`n","`n")); break }
        "Hex"   { $BinaryData = $HexString.ToLower() -replace '[\s-]' -split '([a-f0-9]{2})' | ? { $_ } | % { [System.Convert]::ToByte($_, 16) }; break }
    } 

    $idx = 0
    $XORcryption = foreach($Byte in $BinaryData) {
                        if ($idx -eq $KeyPhrase.Length) { $idx = 0 }
                        $Byte -bxor [byte][char]($KeyPhrase[$idx])
                        $idx++
                    }
    
    if ($AsString) { [Text.Encoding]::UTF8.GetString($XORcryption) }
    else { [BitConverter]::ToString($XORcryption).ToLower() -replace '-' }
}

Function Get-HammingDistance
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0 )]
        [byte[]]$Bytes1,

        [Parameter( Mandatory = $True, Position = 1 )]
        [byte[]]$Bytes2
    )
    $Distance = 0
    $Bin1 = $(foreach($b in $Bytes1) { [Convert]::ToString($b,2).PadLeft(8,'0') }) -join ''
    $Bin2 = $(foreach($b in $Bytes2) { [Convert]::ToString($b,2).PadLeft(8,'0') }) -join ''
    foreach ($i in (0..($Bin1.Length-1))) { if ($Bin1[$i] -ne $Bin2[$i]) { $Distance++ } }    
    $Distance
}

Function Get-KeySize
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0 )]
        [Byte[]]$Data,
        
        [Parameter( Mandatory = $True, Position = 1 )]
        [Int[]]$KeySizeRange
    )
    $Scores = @()
    Foreach($KeySize in $KeySizeRange)
    {

        $BlockCount = [Math]::Floor($Data.Length / $KeySize) / 2
        $Score = (0..($BlockCount-1) | 
                    % { 
                        $Hamming1, $Hamming2, $null = Split-Data $Data[($_*($KeySize*2))..(($_*($KeySize*2))+((2*$KeySize)-1))] -BlockSize $KeySize                                 
                        Get-HammingDistance $Hamming1 $Hamming2
                    } | measure -Sum).Sum
        $Scores += New-Object PSObject -Property @{
                        'KeySize'  = $KeySize
                        'Distance' = $Score
                    } 
    }
    (($Scores | Sort 'Distance')[0]).KeySize
}

Function Invoke-AESECBDecryption
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$EncryptedData,

        [Parameter( Mandatory = $True )]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$KeyData,

        [Parameter( Mandatory = $False )]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$IVData = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
    )
    $AES = New-Object Security.Cryptography.AesManaged
    $AES.KeySize = 128
    $AES.Key     = $KeyData
    $AES.IV      = $IVData
    $AES.Mode    = [Security.Cryptography.CipherMode]::ECB
    $AES.Padding = [Security.Cryptography.PaddingMode]::Zeros

    $Decryptor = $AES.CreateDecryptor()
    $msDecrypt = New-Object IO.MemoryStream @(,$EncryptedData)
    $csDecrypt = New-Object Security.Cryptography.Cryptostream $msDecrypt,$Decryptor,([Security.Cryptography.CryptoStreamMode]::Read)
    $srDecrypt = New-Object IO.StreamReader $csDecrypt
    $srDecrypt.ReadToEnd()
    $srDecrypt.Close()
    $csDecrypt.Close()
    $msDecrypt.Close()
    $AES.Clear()
}

Function Invoke-AESECBEncryption
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$Plaintext,

        [Parameter( Mandatory = $True )]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$KeyData,

        [Parameter( Mandatory = $False )]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$IVData = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
    )
    $AES = New-Object Security.Cryptography.AesManaged
    $AES.KeySize = 128
    $AES.Key     = $KeyData
    $AES.IV      = $IVData
    $AES.Mode    = [Security.Cryptography.CipherMode]::ECB
    $AES.Padding = [Security.Cryptography.PaddingMode]::Zeros

    $Encryptor = $AES.CreateEncryptor()
    $msEncrypt = New-Object IO.MemoryStream
    $csEncrypt = New-Object Security.Cryptography.Cryptostream $msEncrypt,$Encryptor,([Security.Cryptography.CryptoStreamMode]::Write)
    $swEncrypt = New-Object IO.StreamWriter $csEncrypt
    $swEncrypt.Write($Plaintext)
    $swEncrypt.Close()
    $csEncrypt.Close()
    $msEncrypt.Close()
    $AES.Clear()
    [byte[]]$msEncrypt.ToArray() 
}

Function Test-ECBMode
{
    [CmdletBinding()] 
    Param (
        [Parameter( Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String[]]$HexStrings
    )
    $Blocks = @()
    $Result = @{ ECBMode = $False }
    :Main foreach($Line in $HexStrings) 
    {
        for($i = 0; $i -lt $Line.Length; $i += 16)
        {
            $Block = $Line.SubString($i,16)
            if ($Blocks -contains $Block) 
            { 
                $Result.ECBMode   = $true
                $Result.Data      = $Line
                $Result.Duplicate = $Block
                break Main
            }
            $Blocks += $Block
        }
    }
    New-Object PSObject -Property $Result
}
