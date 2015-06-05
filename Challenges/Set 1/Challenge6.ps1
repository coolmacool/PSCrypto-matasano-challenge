if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Import-Module $PSScriptRoot\..\..\PSCrypto -Force

$Data = [Convert]::FromBase64String((Get-Content $PSScriptRoot\6.txt))
$KEYSIZE = Get-KeySize $Data -KeySizeRange (2..40)

Write-Output "Detected KEYSIZE:`t $KEYSIZE"

$Blocks = Split-Data $Data -BlockSize $KEYSIZE
$Transposed = @()
0..($KEYSIZE-1) | % {
    $Transposed += ,@()
    foreach($Block in $Blocks) { $Transposed[$_] += $Block[$_] }
}

$RecoveredKey = ''
$Transposed | % {
    Get-BruteXOR $_ -Keys (0..255) | ? { $_.Score -gt 60 } | select Key, Score | Tee-Object -Variable KeyResult
    $RecoveredKey += $KeyResult.Key
}

Write-Output "Recovered Key:`t $RecoveredKey"
