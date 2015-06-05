if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Import-Module $PSScriptRoot\..\..\PSCrypto -Force

$Data = Get-Content $PSScriptRoot\8.txt 
Test-ECBMode $Data