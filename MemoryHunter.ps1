### Step 1: Pivot from Anomaly Detection to Memory Analysis 
### Step 2: Function to check if space available, split out mem dump
### Step 3: dlllist/dlldump +
### Step 4: VT Query +
### Step 5: malfind
### Step 6: ThreatGrid query +
### Step 7: ThreatGrid logic to see if file already submitted
### Step 8: NSRL Query 
### Step 9: Filescan.io - waiting to hear back on full report details
### Step 10: Detect if proxy set up
### Step 10: Bstrings? or maybe fireeye floss?
### Step 11: yarascan? -maybe just use FileScan.io to optimize
### Step 12: Clean up
### Step 13: files? 508 b3p83
### Step 14: Shellbags? volatility -f victim.raw --profile=Win7SP1x64 shellbags
### Step 15: Create response for S1 investigation
### Ideally I was trying to use direct memory analysis but VMs have issues 


# WinPmem download: https://github.com/Velocidex/WinPmem/releases
# Volatility download: https://www.volatilityfoundation.org/releases
#Requires -RunAsAdministrator

#Install 7Zip Module if it doesn't exist
$test = Get-InstalledModule | findstr 7Zip4Powershell
if($test){}else{Install-Module -Name 7Zip4Powershell -Scope CurrentUser -Force}

#Add in modules
. ./modules/Check-VirusTotal.ps1
. ./modules/Check-NSRL.ps1
. ./modules/Check-FileScanIoHash.ps1
. ./modules/Check-ThreatGridHash.ps1
. ./modules/Submit-ToThreatGrid.ps1

#Create folders if they don't exist
New-Item -ItemType Directory -Path C:\temp\proc\ -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path C:\temp\TG-Submissions\ -ErrorAction SilentlyContinue

#Imports
$TrustedCerts = Import-Csv -Path ./baselines/TrustedCerts.csv #for bypassing
$AnomolousProcs = Import-Csv -Path ./output/Hunting/anomalousProcs.csv
$AnomolousProcsOptimized = @()
$AnomolousDLLsOptimized = @()
$VTPositives = "unknown"

Function Analyze-DLLsFull {
    #dlllist / dlldump #Dumpfiles was missing python package
    $dlllist = .\modules\memory\Volatility\vol3.exe -o "C:\temp\proc" -f "C:\temp\mem.raw" windows.dlllist.DllList --pid 1236 --dump
    foreach($dll in $dlllist){
        $VTPositives = "unknown"
        #Fields: PID  ProcessBase  Size  Name  Path  LoadTime  File output
        $dll = $dll -split("\t")
        $CurrentDllExtraMeta = @()
        $DLLPath = $dll[5]

        #Filter out the header area
        if ($DLLPath -like "*.*"){
            $CurrentDllExtraMeta = $DLLPath | Get-AuthenticodeSignature -ErrorAction SilentlyContinue | ` Select-Object -Property Status,SignerCertificate

            #Filter for valid certs in our baseline
            if (($CurrentDllExtraMeta.Status = "Valid") -and ($CurrentDllExtraMeta.SignerCertificate.Subject -in $TrustedCerts.Subject)){
                #Skip Valid and in Trusted Certs
            }
            else{
                $NSRLCheck = Check-NSRL($dll)
                $NSRLCheck
            }
            <#else{
                $VTPositives = Check-VirusTotal($dll)
                $dll[5]
                Write-Host("$($dll[4]) has $($VTPositives) hits on VT.")

                ###NSRL Query
                
                #TG
                #First we check the original hash to see if it exists
                $DLLPath = "C:\temp\proc\$($dll[4])"
                Check-ThreatGridHash($DLLPath)

                #The we check the zipped hash to see 
                $DLLPath = "C:\temp\proc\$($dll[4])"
                Check-ThreatGridHash($DLLPath)

                $pattern = "*pid.$($dll[0]).$($dll[4])*"
                $BeforeName = Get-Childitem -Path "C:\temp\proc" -Filter $pattern | Select Name
                
                $pattern = "C:\temp\proc$($pattern)"
                if($BeforeName.Name.Count -eq 1){
                    Rename-Item "C:\temp\proc\$($BeforeName.Name)" $dll[4] -ErrorAction SilentlyContinue
                }
                else{
                    Rename-Item "C:\temp\proc\$($BeforeName.Name[0])" $dll[4] -ErrorAction SilentlyContinue
                }
                
                
                Submit-ToThreatGrid($DLLPath)


                #bstrings?
                #report?
            }#>
        }
        else{
            #Skip header area
        }
    }
    
    #Malware
    #Malfind will search for suspicious structures related to malware
    $malfind = .\modules\memory\Volatility\vol3.exe -o "C:\temp\proc" -f "C:\temp\mem.raw" windows.malfind.Malfind --pid 1236 --dump
    if ($malfind.Count -le 4){
        #4 indicates nothing returned on malfind
    }
    else{
Write-Host("malfind results need to be flushed out for hits")
    }
 
    #yarascan
    #./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
    #./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
    #mkdir rules
    #python malware_yara_rules.py
    #Only Windows
    #./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
    #All
    #./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar

    #Netscan seems to hang and doesn't seem to be searchable by pid?
    #$netscan = .\modules\memory\Volatility\vol3.exe -f "C:\temp\mem.raw" windows.netscan.NetScan

    #./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
    #./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
    #./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
    #./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
    #./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
    #./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks

}
Write-Host("Dumping Memory...")
#Dump the memory with WinPmem
#.\memory\WinPmem\winpmem_mini_x64_rc2.exe c:\temp\mem.raw

#Here we build out our anomolous processes / DLLs for analysis
foreach($AnomolousProc in $AnomolousProcs){

    if($AnomolousProc.Reason -match 'is NOT in the DLL baseline list'){
        #This needs to be broken out!
        $AnomolousDLLsOptimized += $AnomolousProc
    }
    else{
        $AnomolousProcsOptimized += $AnomolousProc
    }
}
$AnomolousDLLsOptimized = $AnomolousDLLsOptimized  | Sort-Object -Unique
$AnomolousProcsOptimized = $AnomolousProcsOptimized | Sort-Object -Unique

Write-Host("Processing Memory File...")
Analyze-DLLsFull