if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Import-Module $PSScriptRoot\..\..\PSCrypto -Force

$Encrypted = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736' | Convert-HexToBytes
<#
# Brute force using all possible byte values
$Scores = @()
foreach($i in (0..255))
{
    $Decrypted = ''
    $Failed = $false

    # decrypt (XOR) ciphertext with current key value
    foreach($b in $Encrypted)  
    { 
        $DecryptedValue = $b -bxor $i

        # Check for non-printable ASCII
        if (($DecryptedValue -lt 32 -or $DecryptedValue -gt 126) -and $DecryptedValue -ne 10 -and $DecryptedValue -ne 13)
        {
           $Failed = $true; continue
        }
        $Decrypted += [char]$DecryptedValue
    }

    # string did not contain non-printable ASCII
    if (-not $Failed) 
    { 
        $FreqquencyScore = ($Decrypted | Select-String "[etaoinshrdlu ]" -AllMatches | % { $_.Matches } | % { $_.Value }).Length
        $Scores += New-Object PSObject -Property @{
            'Key Value' = $i
            'Decrypted' = $Decrypted
            'Score'     = $FreqquencyScore
        } 
    }
}

#($Scores | Sort Score -Descending)[0] | fl 
$Scores | ? { $_.Score -ge 22 } | Fl
#>
Get-BruteXOR $Encrypted -Keys (0..255) | ? { $_.Score -ge 22 } | fl

# Winner
#
# Key       : X
# KeyValue  : 88
# Decrypted : Cooking MC's like a pound of bacon
# Score     : 23