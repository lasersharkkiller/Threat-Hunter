### Step 1: Create a baseline of unique DLLs on first gold image +
### Step 2: Compare Name, Directory, Size, Company, Status against baseline +
### Step 3: If not in baseline check for invalid cert +
### Step 4: Then check for null values, if not, check baseline meta +
### Step 5: Then check Hamming / Length Analysis +
### Step 6: Add logic to skip valid, Trusted certs +
### Step 7: Move skipped certs statistical analysis to after known good iterated  +
### Step 8: Write unknown / anomalous to file +
### Step 9: Check if equal to list Issuers but not valid +
### Step 10: Freq.ps1 integration +
### Step 11: Backport to PowerShell v5 +

#############################################################
#######################Define Variables######################
#############################################################
#Requires -RunAsAdministrator

#Import HammingScore Function for name masquerading
# https://github.com/gravejester/Communary.PASM
$HammingScoreTolerance = 2 #Tune our Hamming score output
. ./modules/Get-HammingDistance.ps1
. ./modules/Freq.ps1

#Name Length Tolerance
$LengthTolerance = 6 #.dll is 4 chars
#Frequency Tolerance. Mark uses 5, higher values normal words but for DLLs maybe make lower (based on testing)
$FreqScoreTolerance = 3

#Ability to import the latest definitions from GitHub:
$PullLatestBaseline = $false
if ($PullLatestBaseline){
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/cyb3rpanda/Threat-Hunter/main/baselines/BaselineDLLs.csv' -OutFile './baselines/BaselineDLLs.csv'
}

#Create / Clear our DLL output files
$unknownDLLsfile = './output/Hunting/unknownDLLs.csv'
$anomalousDLLsfile = './output/Hunting/anomalousDLL.csv'
New-Item -ItemType File -Path $unknownDLLsfile -Force | Out-Null
New-Item -ItemType File -Path $anomalousDLLsfile -Force | Out-Null

$BaselineDLLs = Import-Csv -Path ./baselines/BaselineDLLs.csv
$TrustedCerts = Import-Csv -Path ./baselines/TrustedCerts.csv
$TrustedDLLs = @()
$FilesToCheck = @() #We save this to a list and check after building our TrustedDll List
#############################################################
#############################################################
#############################################################

#############################################################
######################Frequency Analysis#####################
#############################################################
Function Hamming-Analysis {
    #Hamming Frequency Analysis against various metadata
    
    #First optimize the baseline we are comparing against
    if ($WhichOne -eq "DLL Name"){
        $TrimmedDownList = $TrustedDLLs.ModuleName | Sort-Object -Unique
    }
    elseif ($WhichOne -eq "Company"){
        $TrimmedDownList = $TrustedDLLs.Company | Sort-Object -Unique
    }
    elseif ($WhichOne -eq "Description"){
        $TrimmedDownList = $TrustedDLLs.Description | Sort-Object -Unique
    }
    elseif ($WhichOne -eq "Subject"){
        $TrimmedDownList = $TrustedDLLs.Subject | Sort-Object -Unique
    }
    elseif ($WhichOne -eq "Issuer"){
        $TrimmedDownList = $TrustedDLLs.Issuer | Sort-Object -Unique
    }
    elseif ($WhichOne -eq "Serial"){
        $TrimmedDownList = $TrustedDLLs.Serial | Sort-Object -Unique
    }
    elseif ($WhichOne -eq "Thumbprint"){
        $TrimmedDownList = $TrustedDLLs.Thumbprint | Sort-Object -Unique
    }

    #Now compare against optimized list
    foreach($line in $TrimmedDownList){

        if ($WhichOne -eq "DLL Name"){
            $BaselineDLLMeta = [string]$line
            $StringRunDLLMeta = [string]$FileToCheck.ModuleName
        }
        elseif ($WhichOne -eq "Company"){
            $BaselineDLLMeta = [string]$line
            $StringRunDLLMeta = [string]$FileToCheck.Company
        }
        elseif ($WhichOne -eq "Description"){
            $BaselineDLLMeta = [string]$line
            $StringRunDLLMeta = [string]$FileToCheck.Description
        }
        elseif ($WhichOne -eq "Subject"){
            $BaselineDLLMeta = [string]$line
            $StringRunDLLMeta = [string]$FileToCheck.Subject
        }
        elseif ($WhichOne -eq "Issuer"){
            $BaselineDLLMeta = [string]$line
            $StringRunDLLMeta = [string]$FileToCheck.Issuer
        }
        elseif ($WhichOne -eq "Serial"){
            $BaselineDLLMeta = [string]$line
            $StringRunDLLMeta = [string]$FileToCheck.Serial
        }
        elseif ($WhichOne -eq "Thumbprint"){
            $BaselineDLLMeta = [string]$line
            $StringRunDLLMeta = [string]$FileToCheck.Thumbprint
        }

        #Do our actual analysis
        if(($BaselineDLLMeta -eq "") -or ($BaselineDLLMeta -eq $StringRunDLLMeta)){
            #Skip if null or exactly equal
        }
        else{
            $HammingScore = Get-HammingDistance $StringRunDLLMeta $BaselineDLLMeta
            if ($HammingScore -le $HammingScoreTolerance){
                $reason += "Similar naming of $($StringRunDLLMeta) but not the same for $($BaselineDLLMeta)"
                $reason

                $whichfile = $anomalousDLLsfile
                $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
                $FileToCheck | Export-CSV -NoTypeInformation $whichfile -Append -Force
            }
        }
    }
}
Function Length-Analysis {
    #Length check of various metadata
        if ($CheckThisLength -le $LengthTolerance){
            $reason = "Short name for $($WhichOne)"
            $reason
            
            $whichfile = $anomalousDLLsfile
            $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
            $FileToCheck | Export-CSV -NoTypeInformation $whichfile -Append -Force
        }
}

Function Freq-Analysis {
    #Use Mark Baggett's Frequency Analysis
    if ($WhichOne -eq "DLL Name"){
        $StringRunDLLMeta = [string]$FileToCheck.ModuleName
        $StringRunDLLMeta = $StringRunDLLMeta -replace ".dll"
        $StringRunDLLMeta = $StringRunDLLMeta -replace ".exe"
    }
    elseif ($WhichOne -eq "Company"){
        $StringRunDLLMeta = [string]$FileToCheck.Company
    }
    elseif ($WhichOne -eq "Description"){
        $StringRunDLLMeta = [string]$FileToCheck.Description
    }
    elseif ($WhichOne -eq "Subject"){
        $StringRunDLLMeta = [string]$FileToCheck.Subject
    }
    elseif ($WhichOne -eq "Issuer"){
        $StringRunDLLMeta = [string]$FileToCheck.Issuer
    }

    $FreqReturn = Get-FrequencyScore -Measure $StringRunDLLMeta
    $FreqScore = $FreqReturn.FrequencyScore -replace "[()]" 
    $FreqScore = $FreqScore -split ","
    $FreqScore = [int]$FreqScore[0]

    if ($FreqScore -le $FreqScoreTolerance){
        $reason = "Naming for $($StringRunDLLMeta) fell outside our frequency tolerance, could be an indicator."
        $reason
                            
        $whichfile = $anomalousDLLsfile
        $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
        $FileToCheck | Export-CSV -NoTypeInformation $whichfile -Append -Force
    }
    else{}

}
#############################################################
#############################################################
#############################################################

#############################################################
#####################Filter Trusted DLLs#####################
#############################################################
Function Filter-TrustedDLLs {
    $reason = ""
    $BaselineDLL

    #Separate module to only do each unique DLL/exe once
    Write-Host("Gathering Currently Loaded Dlls...")
    $CurrentDlls = Get-Process | Select-Object -ExpandProperty Modules | Sort-Object -Unique | Select-Object ModuleName,FileName,Size,Company,Description
    Write-Host("Iterating Through Known Good...")
    foreach($CurrentDll in $CurrentDlls){

        $CurrentDllExtraMeta = Get-ChildItem $CurrentDll.FileName -ErrorAction SilentlyContinue | Get-AuthenticodeSignature | ` Select-Object -Property ISOSBinary,SignatureType,Status,SignerCertificate

        #Skip if valid and in our trust list, then add to our baseline for freq analysis
        if (($CurrentDllExtraMeta.Status -eq "Valid") -and ($CurrentDllExtraMeta.SignerCertificate.Subject -in $TrustedCerts.Subject)){
            $AddThis = New-Object PSObject -Property @{
                ModuleName      = $CurrentDll.ModuleName
                FileName        = $CurrentDll.FileName
                Size            = $CurrentDll.Size
                Company         = $CurrentDll.Company
                Description     = $CurrentDll.Description
                ISOSBinary      = $CurrentDllExtraMeta.ISOSBinary
                SignatureType   = $CurrentDllExtraMeta.SignatureType
                Status          = $CurrentDllExtraMeta.Status
                Subject         = $CurrentDllExtraMeta.SignerCertificate.Subject
                Issuer          = $CurrentDllExtraMeta.SignerCertificate.Issuer
                SerialNumber    = $CurrentDllExtraMeta.SignerCertificate.SerialNumber
                NotBefore       = $CurrentDllExtraMeta.SignerCertificate.NotBefore
                NotAfter        = $CurrentDllExtraMeta.SignerCertificate.NotAfter
                ThumbPrint      = $CurrentDllExtraMeta.SignerCertificate.ThumbPrint
            }
            $TrustedDLLs = $TrustedDLLs + $AddThis
        }

        elseif($CurrentDll.ModuleName -in $BaselineDLLs.ModuleName){
            $reason = ""
            $BaselineDLL = $BaselineDLLs | Where-Object {$_.ModuleName -eq $CurrentDll.ModuleName}
            
            #First Check to make sure it's the same directory
            $CurrentDllFileName = [string]$CurrentDll.FileName
            if(([string]$BaselineDLL.FileName -eq "MULTIPLE") -or ($CurrentDllFileName -eq $BaselineDLL.FileName)){
                #Next we check to make sure it's the same size. Some malware appends to the end of legitamite DLLs
                if([int]$CurrentDll.Size -eq $BaselineDLL.Size){
                    #Next check the company
                    if([string]$CurrentDll.Company -eq $BaselineDLL.Company){
                        #Last check the status
                        if($CurrentDllExtraMeta.Status -eq $BaselineDLL.Status){
                        }
                        else{
                            $whichfile = $anomalousDLLsfile
                            $reason = "$($CurrentDllExtraMeta.Status) was not the same status as our baseline."
                            $reason

                            $CurrentDll | Add-Member -Type NoteProperty -Name "reason" -Value $reason
                        }
                    }
                    #Else Company did not match
                    else{
                        $whichfile = $anomalousDLLsfile
                        $reason = "$($CurrentDll.Company) was not the same size as our baseline. The company did not match"
                        $reason

                        $CurrentDll | Add-Member -Type NoteProperty -Name "reason" -Value $reason
                    }
                }
                #Else we failed the Size Check
                else{
                    $whichfile = $anomalousDLLsfile
                    $reason = "$($CurrentDll.ModuleName) was not the same size as our baseline. Some malware appends to the end of legitamite signed DLLs."
                    $reason

                    $CurrentDll | Add-Member -Type NoteProperty -Name "reason" -Value $reason
                }
            }
            #Else the DLL matched but it failed the directory check
            else{
                $whichfile = $anomalousDLLsfile
                $reason = "$($CurrentDll.FileName) was in the baseline list but didn't match the directory $($BaselineDLL.FileName)."
                $reason

                $CurrentDll | Add-Member -Type NoteProperty -Name "reason" -Value $reason
            }

            if ($whichfile -eq $anomalousDLLsfile){
                $CurrentDll | Export-CSV -NoTypeInformation $whichfile -Append -Force
            }
        }
        #If $CurrentDll.ModuleName -notin $BaselineDLLs.ModuleName look for various indicators
        else{
            $AddThis = New-Object PSObject -Property @{
                ModuleName      = $CurrentDll.ModuleName
                FileName        = $CurrentDll.FileName
                Size            = $CurrentDll.Size
                Company         = $CurrentDll.Company
                Description     = $CurrentDll.Description
                ISOSBinary      = $CurrentDllExtraMeta.ISOSBinary
                SignatureType   = $CurrentDllExtraMeta.SignatureType
                Status          = $CurrentDllExtraMeta.Status
                Subject         = $CurrentDllExtraMeta.SignerCertificate.Subject
                Issuer          = $CurrentDllExtraMeta.SignerCertificate.Issuer
                SerialNumber    = $CurrentDllExtraMeta.SignerCertificate.SerialNumber
                NotBefore       = $CurrentDllExtraMeta.SignerCertificate.NotBefore
                NotAfter        = $CurrentDllExtraMeta.SignerCertificate.NotAfter
                ThumbPrint      = $CurrentDllExtraMeta.SignerCertificate.ThumbPrint
            }
            $FilesToCheck = $FilesToCheck + $AddThis
        }
    }
    #After looping through known good analyze knowns
    Analyze-Unknowns
}
#############################################################
#############################################################
#############################################################

#############################################################
######################Analyze Unknowns#######################
#############################################################
Function Analyze-Unknowns {
    Write-Host("Analyzing unknowns ...")

    foreach($FileToCheck in $FilesToCheck){
        $reason = "$($FileToCheck.ModuleName) Not in our valid trusted certs or baseline. Possible indicators: "
        $whichfile = $unknownDLLsfile
        $FileToCheck | Export-CSV -NoTypeInformation $whichfile -Append -Force

        #Hamming Frequency Analysis Against Module Name, Company, Subject, Issuer, Serial, Thumbprint
        $CheckThisLength = $FileToCheck.ModuleName.Length
        $WhichOne = "DLL Name"
        Length-Analysis($CheckThisLength,$WhichOne,$reason)
        Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne,$reason)
        Freq-Analysis($FileToCheck,$WhichOne,$reason)

        #Next check company (Not part of cert info)
        if ($FileToCheck.Company -eq $null){
            $reason += "Company info is null. "
            $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
            $whichfile = $anomalousDLLsfile
        }
        else{
            $CheckThisLength = $FileToCheck.Company.Length
            $WhichOne = "Company"

            Length-Analysis($CheckThisLength,$WhichOne)
            Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            Freq-Analysis($FileToCheck,$WhichOne)
        }

        #Next check description (Not part of cert info)
        if ($FileToCheck.Description -eq $null){
            $reason += "Description info is null. "
            $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
            $whichfile = $anomalousDLLsfile
        }
        else{
            $CheckThisLength = $FileToCheck.Description.Length
            $WhichOne = "Description"

            Length-Analysis($CheckThisLength,$WhichOne)
            Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            Freq-Analysis($FileToCheck,$WhichOne)
        }


        #Next check certificate info, and if exists analysis meta
        if($FileToCheck.Status -eq "NotSigned"){
            $reason += "Not signed. "

            $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
            $whichfile = $anomalousDLLsfile
        }

        else{
            #Invalid certs
            if(($FileToCheck.Status -ne "Valid") -and ($FileToCheck.Issuer -in $TrustedDLLs.Issuer)){
                $reason += "Issued by a trusted issuer, but not a valid certificate. Some malware appends to legitamite DLLs. "
                $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
                $whichfile = $anomalousDLLsfile
            }

            #Invalid certs
            elseif([string]$FileToCheck.Status -ne "Valid"){
                $reason += "Not a valid certificate. "
                $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
                $whichfile = $anomalousDLLsfile
            }
            
            if ($FileToCheck.Subject -eq $null){
                $reason += "Subject info is null. "
                $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CheckThisLength = $FileToCheck.Subject.Length
                $WhichOne = "Subject"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
                Freq-Analysis($FileToCheck,$WhichOne)
            }

            if ($FileToCheck.Issuer -eq $null){
                $reason += "Issuer info is null. "
                $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CurrentDllExtraMeta = $FileToCheck.Issuer.Length
                $WhichOne = "Issuer"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
                Freq-Analysis($FileToCheck,$WhichOne)
            }

            if ($FileToCheck.Serial -eq $null){
                $reason += "Serial info is null. "
                $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CheckThisLength = $FileToCheck.Serial.Length
                $WhichOne = "Serial"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            }

            if ($FileToCheck.Thumbprint -eq $null){
                $reason += "Thumbprint info is null. "
                $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason -Force
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CheckThisLength = $FileToCheck.Thumbprint.Length
                $WhichOne = "Thumbprint"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            }
        }
        #$FileToCheck | Export-CSV -NoTypeInformation $whichfile -Force –Append
    }
}
#############################################################
#############################################################
#############################################################

#Invoke the main DLL Analysis function
Filter-TrustedDLLs