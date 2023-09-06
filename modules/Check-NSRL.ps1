Function Check-NSRL {
    
    $test = Test-Path ./modules/NSRL/NSRL-SHA1.csv
    if($test){}else{Invoke-WebRequest -URI https://www.dropbox.com/s/pr2lvfneoxjgvab/NSRL-SHA1.csv?dl=0 -OutFile ./modules/NSRL/NSRL-SHA1.csv}

    $fileHash = Get-FileHash -Algorithm SHA1 ($DLLPath)
    $NSRLCheck = Import-Csv -Path "./modules/NSRL/NSRL-SHA1.csv" | Where-Object {$_.sha1 -eq $fileHash}
    $NSRLCheck = [bool]$NSRLCheck
    return($NSRLCheck)
}