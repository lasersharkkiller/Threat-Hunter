    <#
        .DESCRIPTION
            This is a port of Mark Baggett's freq.py into PowerShell! See https://github.com/MarkBaggett/freq for the inspiration. The Security Onion integration has been so powerful that the goal here is to extend availability of the technique to Blue Teamers doing initial triage and analysis via PowerShell.

Use cases involve analyzing process names, file names, services, etc.
        .EXAMPLE
            PS C:\> Get-Process | Get-FrequencyScore -Property Name | Select-Object -Property ProcessName,FrequencyScore -Unique
        .LINK
            https://github.com/jcjohnson34/Freq-PS
        .NOTES
            Authors: jcjohnson34, MarkBaggett
    #>
Class FreqCounter {
    $table
    [switch]$ignore_case = $false
    [String]$ignorechars = "~`!@#$%^&*()_+-"

    FreqCounter(){
        
    }
    [void] SaveTable([String]$filename){
        #To Do: Provide option to save table in format that can be read into Freq.py
        $this | ConvertTo-Json -Compress | Out-File $filename
    }
    [void] CreateTable([String]$filename){

        $TableContent = Get-Content $filename
        $this.table = New-Object -TypeName System.Collections.Hashtable        
        foreach($line in $TableContent){
            $this.TallyString($line)
        }
    }
    [void] TallyString($line){
        $weight = 1
        $allPairs = @()

        for($ctr=0;$ctr -lt $line.Length;$ctr++){
            $char1 = $line[$ctr].ToString().ToLower()
            if($line[$ctr+1]){
                $char2 = $line[$ctr+1].ToString().ToLower()
                $allPairs += $char1+$char2
            }
        }
        foreach($pair in $allPairs){
            if($this.table.containsKey("$($pair[0])") -and $this.table["$($pair[0])"].containsKey("$($pair[1])")){
                $this.table["$($pair[0])"]["$($pair[1])"]++
            }
            else{
                if(!$this.table.ContainsKey("$($pair[0])")){
                    $this.table["$($pair[0])"]=New-Object -TypeName System.Collections.Hashtable
                }
                $this.table["$($pair[0])"]["$($pair[1])"]= New-Object -TypeName System.Collections.Hashtable
                $this.table["$($pair[0])"]["$($pair[1])"] = $weight
            }
        }
    }
    [void] LoadHashTable ([string]$filename){
        $Content = Get-Content -Path $filename
        
        try { #Python-based Export method
            $json = $Content | ConvertFrom-Json

            $this.ignore_case = $json[0]
            $this.ignorechars = $json[1].trim()
            
            $frequencyTable = New-Object -TypeName System.Collections.Hashtable
            $primaryObjects = $json[2] | Measure-Object | Select-Object -ExpandProperty count
            for($ctr = 0; $ctr -lt $primaryObjects; $ctr ++){
                $primaryLetter = $json[2][$ctr][0]
                $secondaryObjects = $json[2][$ctr][1] | Measure-Object | Select-Object -ExpandProperty count
                $frequencyTable["$primaryLetter"]=New-Object -TypeName System.Collections.Hashtable
                for($secondaryCtr = 0; $secondaryCtr -lt $secondaryObjects; $secondaryCtr++){
                    $secondaryLetter = $json[2][$ctr][1][$secondaryCtr][0]
                    $secondaryLetterCount = $json[2][$ctr][1][$secondaryCtr][1]
                    $frequencyTable["$primaryLetter"]["$secondaryLetter"]= New-Object -TypeName System.Collections.Hashtable
                    $frequencyTable["$primaryLetter"]["$secondaryLetter"]=[int]$secondaryLetterCount
                }
            }
            $this.table = $frequencyTable  
        }
        catch{ #PowerShell-based Export method
            $this = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($Content)
        }
           
    }
    [String] ScoreProbability([String]$chars){
        $allPairs = @()
        $probabilities = New-Object System.Collections.ArrayList
        $Average_Probability = 0 
        $total_word_probability = 0

        $ctr = 0
        for($ctr=0;$ctr -lt $chars.Length;$ctr++){
            $char1 = $chars[$ctr]
            $char2 = $chars[$ctr+1]
            $allPairs += $char1+$char2
        }

        foreach($pair in $allPairs){
           if($pair[0] -notin $this.ignorechars -and $pair[1] -and $pair[1] -notin $this.ignorechars){
               $probabilities.Add($this.CalculatePairProbability($pair))
           }
        }

        if($probabilities.Count -gt 0){
            $sumProb = 0
            $numProbs = $probabilities.Count
            foreach($prob in $probabilities){
                $sumProb += $prob
            }
            $Average_Probability = $sumProb/$numProbs*100
        }
        $totl1 = $totl2 = 0
        foreach($pair in $allPairs){

            $l1 = $l2 = 0
            if($pair[0] -notin $this.ignorechars -and $pair[1] -notin $this.ignorechars -and ($pair[0] -and $pair[1])){
                Write-Verbose "PAIR = $($pair[0]) + $($pair[1])"
                $FirstLower=$pair[0].ToString().ToLower()
                $FirstUpper=$pair[0].ToString().ToUpper()
                $SecondLower=$pair[1].ToString().ToLower()
                $SecondUpper=$pair[1].ToString().ToUpper()
                $prob1_lower = $this.table["$FirstLower"]
                $prob1_upper = $this.table["$FirstUpper"]
                foreach($row in $prob1_lower.Values){
                    $l1+=$row
                }
                foreach($row in $prob1_upper.Values){
                    $l1+=$row
                }

                $l2 = $this.table["$FirstLower"]["$SecondLower"] + $this.table["$FirstLower"]["$SecondUpper"] + $this.table["$FirstUpper"]["$SecondLower"] + $this.table["$FirstUpper"]["$SecondUpper"] 
                
                $totl1 += $l1
                $totl2 += $l2

                Write-Verbose "Letter1:$totl1 Letter2:$totl2 - This pair $($pair[0]):$l1 $($pair[1]):$l2"
            }
            if($totl1 -eq 0 -or $totl2 -eq 0){
                $total_word_probability = 0
            }
            else{
                $total_word_probability = $totl2/$totl1 * 100
            }
        }
        $Result = "($([math]::Round($Average_Probability,4)),$([math]::Round($total_word_probability,4)))"
        return $Result
    }

    [double] CalculatePairProbability ([string]$chars){
        $ignored_total = 0
        $FirstLower=$chars[0].ToString().ToLower()
        $FirstUpper=$chars[0].ToString().ToUpper()
        $SecondLower=$chars[1].ToString().ToLower()
        $SecondUpper=$chars[1].ToString().ToUpper()

        foreach($letter in $this.ignorechars.ToCharArray()){

            $value = $this.table["$FirstLower"]["$letter"]
            $value += $this.table["$FirstUpper"]["$letter]"]
            foreach($val in $value){
                $ignored_total += $val
            }
        }
        Write-Verbose "Ignored Total:  $ignored_total"
        $prob2 = $this.table["$firstLower"]["$secondLower"] + $this.table["$firstLower"]["$secondUpper"] + $this.table["$firstUpper"]["$secondLower"] + $this.table["$firstUpper"]["$secondUpper"]

        $prob1_lower = $this.table["$firstLower"].Values
        $prob1_upper = $this.table["$firstUpper"].Values
        $prob1=0
        foreach($l in $prob1_lower){
            $prob1+=$l
        }
        foreach($u in $prob1_upper){
            $prob1+=$u
        }

        Write-Verbose "Probability 2: $prob2"
        Write-Verbose "Probability 1: $prob1"
        $CalculatedProbability = $prob2/($prob1-$ignored_total)
        Write-Verbose "Calculated Prob for $chars = $CalculatedProbability"

        return $CalculatedProbability
    }
    
}
function Get-FrequencyScore(){ 
    [cmdletbinding()]
    param(
    [parameter(
        Mandatory         = $true,
        ValueFromPipeline = $true)]
        $Measure,
    [parameter(
        Mandatory=$false,
        ValueFromPipeline=$false)]
        $Property,
    [parameter(
        Mandatory=$false,
        ValueFromPipeline=$false)]
        $frequencyTable = ".\modules\freqtable2018.freq"
    )
    Begin {
            $fc = New-Object -TypeName FreqCounter
            $fc.LoadHashTable($frequencyTable)
    }
    Process {
        foreach($input in $Measure){
            if($Property){
                $Result = $fc.ScoreProbability($Measure.$Property)
            }
            else{
                $Result = $fc.ScoreProbability($Measure)
            }

            $input | Add-Member -NotePropertyName FrequencyScore -NotePropertyValue $Result

            if(!$Property){
                $RetObject = [PSCustomObject]@{
                    InputValue = $input
                    FrequencyScore = $Result
                }
                Write-Output $RetObject
            }
            else{
                Write-Output $input
            }
        }
    }
    End { 
        Write-Verbose "Done processing items"
    }
}