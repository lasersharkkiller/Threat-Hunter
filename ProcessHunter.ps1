### Step 1: Enumerate process with forensics artifacts according to SANS 508 +
### Step 2: Build in core processes from SANS 508 Known Normal Poster +
### Step 3: Add logic to compare baseline paths, # instances, user context +
### Step 4: Cross Reference Echo Trails for unknowns +
### Step 5: Add ability to output results to file(s) +
### Step 6: Set Reference File to match additional Echo Trails metadata +
### Step 7: Clean up & future proof variables being passed between functions +
### Step 8: Add check for parent process; figure out logic to parse multiple parents +
### Step 9: Logic for when Echo Trails doesn't recognize a process +
### Step 10: Hamming Frequency analysis to look for similar naming +
### Step 11: Add reasons for failures +
### Step 12: Ability to download latest application definitions +
### Step 13: Add DLL baselining for applications +
### Step 14: Restructure Output to not show positive matches +
### Step 15: Add Name Length Analysis +
### Step 16: Separate DLL Baselining  - Create separate function +
### Step 17: Add logic for services that should run as user that run as something else +
### Step 18: Force running as root +
### Step 19: Add frequency analysis like freq.py against service names +
### Step 20: Logic for when Echo Trails API key errors +
### Step 21: Backport to PowerShell v5 +
### Step 22: Pivot to memory analysis for anomalous processes
### Step 23: Add PS-Remoting
### Step 24: After PS-Remoting, add host to Output Results
### Step 25: Add GUI with parameters (download-may need to offer ability to diffmerge baselines, enter Echo Trails API key, Tune the Hamming Distance, etc)
### Step 26: Add separate module for Sigma hunting
### Possible: Scheduled tasks and new services are top places to look, perhaps add analysis module? (508 b2 p94)
### Possible: PS alternative to DensityScout? / entropy analysis (508 b4p9)
### Possible: Add capa to flow (508 b4p14-16)?
### Possible: Add Long Tail analysis to anomalous results? or leave to Kansa?
###             -508 b2p28 and Lab 2.1 maybe port tcorr, leven, stack, rndsearch? gravejester - PS
### Possible: In future maybe add non-ephemeral network ports baseline? - Lab4.3 might be good reference; also lab5.2
### Possible: Add Get-ProcessMitigation <app> info (586 b4p23)?
### Possible: forensics b1p60 common malware names -covered under DLLHunter? & locations? or maybe sigma rule
### Possible: Volatility can do shellbags? https://infosecwriteups.com/forensics-memory-analysis-with-volatility-6f2b9e859765
### Possible: Analyze prefetch files with same anomaly logic? (508 Lab 2.1) - or diffmerge prefetch with amcache to optimize redundancy?
### Possible: Analyze shimcache with same anomaly logic? (508 Lab 2.1) or amcache since written to registry and tracks DLL info too (508 b2p18)
### Possible: Service log anomalous ids to indicators? (508 b2p101)

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
$ProcNameLengthTolerance = 6 #.exe is 4 chars
#Frequency Tolerance. Mark uses 5, higher values normal words
$FreqScoreTolerance = 5

#Ability to import the latest definitions from GitHub:
$PullLatestBaseline = $false
if ($PullLatestBaseline){
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/cyb3rpanda/Threat-Hunter/main/baselines/CoreProcessesBaseline.csv' -OutFile './baselines/CoreProcessesBaseline.csv'
}

#Define Echo Trails API Key 
$ETkey = "0pWySfWK530M3pWAvcipaUsNyxNF9wC9AIVDma12"

#Create / Clear our process output files
$goodProcsfile = './output/Hunting/goodProcs.csv'
$unknownProcsfile = './output/Hunting/unknownProcs.csv'
$anomalousProcsfile = './output/Hunting/anomalousProcs.csv'
$fullDataNotReturnedProcs = './output/Hunting/fullDataNotReturnedProcs.csv'
$whichfile
New-Item -ItemType File -Path $goodProcsfile -Force | Out-Null
New-Item -ItemType File -Path $unknownProcsfile -Force | Out-Null
New-Item -ItemType File -Path $anomalousProcsfile -Force | Out-Null
New-Item -ItemType File -Path $fullDataNotReturnedProcs -Force | Out-Null

#Keep track of current running Proc looking at
$RunningProcess
$Process
$loadedDLL = ""
$reason
$MultipleParentTest = $false
#Import the CSV and normalize the data, for now null & multiple values in a cell
$CoreProcesses = Import-Csv -Path ./baselines/CoreProcessesBaseline.csv
foreach ($process in $CoreProcesses) {

    if (($process.ImagePath -eq "null") -or ($process.ImagePath -eq "")){
        $process.ImagePath = $null
    }
    if (($process.parentProc -eq "null") -or ($process.parentProc -eq "")){
        $process.parentProc = $null
    }
    if (($process.NumberOfInstances -eq "null") -or ($process.NumberOfInstances -eq "")){
        $process.NumberOfInstances = $null
    }
    if (($process.UserAccount -eq "null") -or ($process.UserAccount -eq "")){
        $process.UserAccount = $null
    }
    if (($process.LoadedDlls -eq "null") -or ($process.LoadedDlls -eq "")){
        $process.LoadedDlls = $null
    }
    if (($process.ChildProcs -eq "null") -or ($process.ChildProcs -eq "")){
        $process.ChildProcs = $null
    }
    if (($process.GrandParentProcs -eq "null") -or ($process.GrandParentProcs -eq "")){
        $process.GrandParentProcs = $null
    }
    if (($process.Ports -eq "null") -or ($process.Ports -eq "")){
        $process.Ports = $null
    }
    if (($process.Notes -eq "null") -or ($process.Notes -eq "")){
        $process.Notes = $null
    }
}
#############################################################
#############################################################
#############################################################


#############################################################
#########################Append CSV##########################
#############################################################
Function Append-CSV {
    $csvfile
    #Processes matching baseline and unknowns have regular minimal data
    if (($whichfile -eq $goodProcsfile)){
        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            NumberOfInstances = $RunningProcess.NumberOfInstances
            UserAccount = $RunningProcess.Owner
            Reason = $reason
        }
    }
    #Processes without full data include a reason column
    elseif (($whichfile -eq $fullDataNotReturnedProcs) -or ($whichfile -eq $unknownProcsfile)) {
        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            ParentProcessId = $RunningProcess.ParentProcessID
            ParentProcess = $RunningProcess.ParentProcess
            NumberOfInstances = $RunningProcess.NumberOfInstances
            UserAccount = $RunningProcess.Owner
            Reason = $reason
        }
    }
    #Anomalous processes
    elseif ($whichfile -eq $anomalousProcsfile) {
        $csvfile = [PSCustomObject]@{
            ProcessName         = $RunningProcess.Name
            ExpectedProcessName = $CoreProcess.procName
            ProcessId           = $RunningProcess.ProcessId
            Path                = $RunningProcess.Path
            ExpectedPath        = $CoreProcess.ImagePath
            ParentProcessId     = $RunningProcess.ParentProcessID
            ParentProcess       = $RunningProcess.ParentProcess
            ExpectedParent      = $CoreProcess.parentProc
            NumberOfInstances   = $RunningProcess.NumberOfInstances
            ExpectedNumberofInstances = $CoreProcess.NumberOfInstances
            UserAccount         = $RunningProcess.Owner
            ExpectedUserAccount = $CoreProcess.UserAccount
            AnomalousLoadedDLL  = $loadedDLL
            #ExpectedParentProc = $parentProc
            ExpecteDChildProcs  = $childProcs
            ExpectedGrandParentProcs = $grandParentProcs
            ExpectedPorts       = $ports
            Reason              = $reason
            Notes               = $intel
        }
    }
    else{
        break
    }
    
    $csvfile | Export-CSV -NoTypeInformation $whichfile -Append -Force
}

Function Append-CSV-EchoTrails {
    #Processes matching baseline and unknowns have regular minimal data

        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ExpectedProcessName = $RunningProcess.Name
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            ExpectedPath =  $results.paths[0][0] + "\" + $RunningProcess.Name
            ParentProcessId = $RunningProcess.ParentProcessID
            ParentProcess = $RunningProcess.ParentProcess
            ExpectedParent = $results.parents[0][0]
            NumberOfInstances = $RunningProcess.NumberOfInstances
            ExpectedNumberofInstances = "ET doesn't have this data"
            UserAccount = $RunningProcess.Owner
            ExpectedUserAccount = "ET doesn't have this data"
            ExpectedChildProcs = ($results.children | Select-Object | Out-String)
            ExpectedGrandParentProcs = ($results.grandparents | Select-Object | Out-String)
            ExpectedPorts = ($results.network | Select-Object | Out-String)
            Reason = $reason
            Notes = $results.$intel
        }
    
    $csvfile | Export-CSV -NoTypeInformation $whichfile -Append -Force
}

Function Append-CSVAnalysis {
    #Processes matching baseline and unknowns have regular minimal data
        
        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ExpectedProcessName = $StringCoreProcName
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            ParentProcessId = $RunningProcess.ParentProcessID
            ParentProcess = $RunningProcess.ParentProcess
            NumberOfInstances = $RunningProcess.NumberOfInstances
            UserAccount = $RunningProcess.Owner
            Reason = $reason
        }
    
    $csvfile | Export-CSV -NoTypeInformation $whichfile -Append -Force
}
#############################################################
#############################################################
#############################################################

Function Set-StyleRootProcs {
        #Write-Output "-  Name: $($_.Name)"
        #Write-Output "    id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Process Instances: ($($RunningProcess.NumberOfInstances)) Process Owner: ($($RunningProcess.Owner))"
        Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth 1
}

Function Set-StyleChildrenProcs {
        #$retTab + "-  Name: $($_.Name)"
        #$retTab + "   id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Process Instances: ($($RunningProcess.NumberOfInstances)) Process Owner: ($($RunningProcess.Owner))"
}
#############################################################
#############################################################
#############################################################


#############################################################
######################Echo Trails Logic######################
#############################################################
Function Check-EchoTrails-ChildrenProcs {
    #Look mostly at first results for each metadata
    $ImagePath = $results.paths[0][0] + "\" + $RunningProcess.Name

    #Right now it only checks the image path, not # instances or the user context
    if(($RunningProcess.Path -eq $ImagePath) -or ($RunningProcess.Path -contains 'C:\Users\' -and $ImagePath -contains 'C:\Users\') -or ($RunningProcess.Path -contains "C:\ProgramData" -and $ImagePath -contains 'C:\ProgramData\')){
            #$retTab + "-  Name: $($_.Name)"
            #$retTab + "   id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Instances: ($($RunningProcess.NumberOfInstances)) Owner: ($($RunningProcess.Owner))"

            #Add to file
            $whichfile = $goodProcsfile
            Append-CSV-EchoTrails($($results))
    }
    else{
            #$retTab + "-  Name: $($_.Name)"
            #$retTab + "   id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Instances: ($($RunningProcess.NumberOfInstances)) Owner: ($($RunningProcess.Owner))"

            #Add to file
            $whichfile = $anomalousProcsfile
            Append-CSV-EchoTrails($($results))
    }
}

Function Check-EchoTrails-RootProcs {
    #Look mostly at first results for each metadata
    $ImagePath = $results.paths[0][0] + "\" + $RunningProcess.Name

    #Right now it only checks the image path, not # instances or the user context
    if(($RunningProcess.Path -eq $ImagePath) -or ($RunningProcess.Path -contains 'C:\Users\' -and $ImagePath -contains 'C:\Users\') -or ($RunningProcess.Path -contains "C:\ProgramData" -and $ImagePath -contains 'C:\ProgramData\')){
        #Add to file
        $whichfile = $goodProcsfile
        Append-CSV-EchoTrails($($results))
    }
    else{
        #Add to file
        $whichfile = $anomalousProcsfile
        Append-CSV-EchoTrails($($results))
    }
    Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth 1
}
#############################################################
#############################################################
#############################################################

#############################################################
######################Frequency Analysis#####################
#############################################################
Function Hamming-Analysis-Procs {
    #Processes matching baseline and unknowns have regular minimal data
    foreach($line in $CoreProcesses){
        $StringCoreProcName = [string]$line.procName
        $StringRunProcName = [string]$RunningProcess.Name
        $HammingScore = Get-HammingDistance $StringRunProcName $StringCoreProcName
        if ($HammingScore -le $HammingScoreTolerance){
            $reason = "Similar to baseline service name"
                            
            $whichfile = $anomalousProcsfile
            Append-CSVAnalysis($StringCoreProcName)
            if($parentvschild = "child"){
                Set-StyleChildrenProcs
            }
            else{
                Set-StyleRootProcs
            } 
        }
    }
}

Function Length-Analysis-Procs {
    #Processes matching baseline and unknowns have regular minimal data
        $ProcNameLength = [int]$RunningProcess.Name.Length
        
        if ($ProcNameLength -le $ProcNameLengthTolerance){
            $reason = "Short name could be an indicator."
                            
            $whichfile = $anomalousProcsfile
            Append-CSVAnalysis($RunningProcess)
            if($parentvschild = "child"){
                Set-StyleChildrenProcs
            }
            else{
                Set-StyleRootProcs
            } 
        }
}

Function Freq-Analysis {
    #Use Mark Baggett's Frequency Analysis
    $FreqReturn = Get-FrequencyScore -Measure $RunningProcess.Name 
    $FreqScore = $FreqReturn.FrequencyScore -replace "[()]" 
    $FreqScore = $FreqScore -split ","
    $FreqScore = [int]$FreqScore[0]
    if ($FreqScore -le $FreqScoreTolerance){
        $reason = "Naming fell outside our frequency tolerance, could be an indicator."
                            
        $whichfile = $anomalousProcsfile
        Append-CSVAnalysis($RunningProcess)
    }
    else{}

}
#############################################################
#############################################################
#############################################################

Write-Output("Beginning Running Process Analysis...")
$allProcesses = Get-CimInstance -ClassName Win32_Process | Select-Object -Property Name,ProcessId,Path,HandleCount,WorkingSetSize,ParentProcessId,CreationDate,CommandLine,UserName

$allProcesses | ForEach-Object {
    $reason = ""
    #Count instances
    $matchThis = $_.Name
    $Process = $allProcesses | Where-Object {$matchThis -eq $_.Name}
    $tempNum = [string](($Process | Measure-Object).Count)

        #get owner
        $pidQuery = Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE ProcessID = `'$($_.ProcessId)`'"
        $owner = Invoke-CimMethod -InputObject $pidQuery -MethodName GetOwner
        $RunningProcess = [PSCustomObject]@{
            PSTypename      = "ProcessHunting"
            ProcessID       = $_.ProcessID
            Name            = $_.Name
            Path            = $_.Path
            Handles         = $_.HandleCount
            WorkingSet      = $_.WorkingSetSize
            ParentProcessID = $_.ParentProcessID
            ParentProcess   = $parent.Name #these are root level procs
            ParentPath      = $parent.Path #these are root level procs
            LoadedDlls      = ""
            Started         = $_.CreationDate
            Owner           = "$($owner.Domain)\$($owner.user)"
            CommandLine     = $_.Commandline
            NumberOfInstances = $tempNum
        }
    
    #Check to see if it is in our core defined processes or if we need to get info from Echo Trails
    if($_.Name -in $CoreProcesses.procName){
        $runningProc = $_.Name
        $CoreProcess = $CoreProcesses | Where-Object {$runningProc -eq $_.procName}

        #First Logic: Check the Path of the Executable. Note some values are null, especially root processes
        if(($CoreProcess.ImagePath -eq "MULTIPLE") -or ($RunningProcess.Path -eq $CoreProcess.ImagePath) -or ($RunningProcess.Path -contains 'C:\Users\' -and $CoreProcess.ImagePath -contains 'C:\Users\') -or ($RunningProcess.Path -contains "C:\ProgramData" -and $CoreProcess.ImagePath -contains 'C:\ProgramData\')){
            if (($CoreProcess.NumberOfInstances -eq 1 -and $RunningProcess.NumberOfInstances -eq $CoreProcess.NumberOfInstances) -or ($CoreProcess.NumberOfInstances -eq 2)) {

                #Note this code block mostly checks for systems that should be running specifically under SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
                if (($CoreProcess.UserAccount -eq "MULTIPLE") -or ($CoreProcess.UserAccount -eq "SYSTEM" -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq $null -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "LOCAL SERVICE" -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "NETWORK SERVICE" -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -notin "SYSTEM","LOCAL SERVICE","NETWORK SERVICE" -or $CoreProcess.UserAccount -ne $null)){
                        $whichfile = $goodProcsfile

                        ###Check all loaded DLLs per proc against baseline data; note DLL baseline location separate function
                        if($CoreProcess.LoadedDlls -eq $null){
                            #Write-Host("($($RunningProcess.Name)) baseline loaded dlls has a null value")
                        }
                        else{
                            $processModules = Get-Process -Id $RunningProcess.ProcessID|Select-Object modules

                            $CoreProcess.LoadedDlls = $CoreProcess.LoadedDlls.split(",")
                            
                            foreach ($loadedDLL in $processModules.modules.ModuleName){
                                #First Loop Through and See if it's in the baseline
                                if ($loadedDLL -in $CoreProcess.LoadedDlls){

                                }
                                elseif($CoreProcess.LoadedDlls -eq "MULTIPLE"){
                                    #NOT Baselineable, like svchost
                                }
                                else{
                                    $reason += "($($loadedDLL)) is NOT in the DLL baseline list for $($CoreProcess.ProcName)"
                                    $whichfile = $anomalousProcsfile
                                    
                                #Set-StyleRootProcs
                                }
                            } 
                        }
                        Append-CSV
                        #Changed from Set-StyleRootProcs to below to suppress output
                        #Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth 1
                }
                else{
                        $reason = "Different User Context than expected"
                        #Set-StyleRootProcs
                        
                        #Add to file
                        $whichfile = $anomalousProcsfile
                        Append-CSV
                }

            }
            else{
                    $reason = "Number of instances did not match"
                    #Set-StyleRootProcs

                    #Add to file
                    $whichfile = $anomalousProcsfile
                    Append-CSV
            }

        }
        else{
            #First check if the value was null
            if($RunningProcess.Path -eq $null){
                $reason = "Expected a Path but our query returned a null value"
                #Set-StyleRootProcs

                #Add to file
                $whichfile = $fullDataNotReturnedProcs
                Append-CSV(($reason))
            }

            else{
                    $reason = "Paths did not match"
                    #Set-StyleRootProcs

                    #Add to file
                    $whichfile = $anomalousProcsfile
                    Append-CSV
            }
        }
    }
    else{

        #Before checking Echo Trails, analyze name frequency against baseline procs
        $parentvschild = "parent"
        Hamming-Analysis-Procs($parentvschild)
        Length-Analysis-Procs($parentvschild)
        Freq-Analysis($parentvschild)

        #Test Echo Trails
        $skipifTrue = "False"
        $tempUri = 'https://api.echotrail.io/v1/private/insights/' + $_.Name
        $results = ""

        try {
            $results = Invoke-RestMethod -Headers @{'X-Api-key' = $ETkey} -Uri $tempUri
            if ($results.message)
                {
                    $skipifTrue = "True"
                    $reason = $results.message
                    $whichfile = $unknownProcsfile
                    Append-CSV
                }
        } 
        catch {
            if ([string]$Error[0] -eq "The remote certificate is invalid because of errors in the certificate chain: PartialChain"){
                Write-Host("Error reaching out to Echo Trails. You probably have a proxy causing this error.")
                #Write-Warning $Error[0] #don't need this, replaced with our own message

                $reason = "Error reaching out to Echo Trails. You probably have a proxy causing this error."
                $whichfile = $unknownProcsfile
                Append-CSV

                $skipifTrue = "True"
            }
            else{
                #Write-Warning $Error[0]
                $reason = "Error reaching Echo Trails."
                $reason += [string] $Error[0]
                $whichfile = $unknownProcsfile
                Append-CSV

                $skipifTrue = "True"
            }
        }

        if($skipifTrue = "True"){}
        elseif ($results){
            Check-EchoTrails-ChildrenProcs($($results))
            $results = $null
        }
        else{
                #White Indicates No Baseline Data
                #Set-StyleRootProcs
                $reason = "No baseline data"
            
                #Add to file
                $whichfile = $unknownProcsfile
                Append-CSV
        }

    }
}