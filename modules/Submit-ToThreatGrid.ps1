##### Status: Complete #####
#
# Script Author: Cyber Panda
#
# ThreatGrid variables: $key $currentfile $password and $files folder
# Also make sure c:\scripts exists if you log errors to $txt_file
# You may need to adjust the sleep period before downloading threat files (Start-Sleep...)

# Pre-Reqs
# Install-Module -Name 7Zip4Powershell

Function Submit-ToThreatGrid{

#for unzip/rezip (password issues)
#Install-Module -Name 7Zip4Powershell -Scope CurrentUser -Force
Import-Module -Name 7Zip4Powershell

###############################
#                             #
#    ThreatGrid Submission    #
#                             #
###############################

###ThreatGrid API key
$key = "enter"
$password = "infected"
#$files = Get-ChildItem "C:\bits\" -Filter *.zip

###API header variable
$api_headers = @{
"Content-Type"="multipart/form-data"
"User-Agent"="ThreatGrid API Script"
"Accept"="*/*"
"Cache-Control"="no-cache"
"Host"="panacea.threatgrid.com"
"Accept-Encoding"="gzip, deflate"
}

###FILE Operation
    Compress-7Zip $DLLPath -ArchiveFileName "$($DLLPath).zip" -Format Zip -Password "infected"
    $newfile = Get-ChildItem "C:\temp\proc\" -Filter *.zip
    $filetosend = $newfile[0].FullName

	    # Read the file contents in as a byte array
		$fileName = Split-Path $filetosend -leaf
        $FilePath = Split-Path $filetosend -Parent
        $bytes = Get-Content $filetosend -Encoding Byte
		$enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
		$FileContent = $enc.GetString($bytes)

		# Body of the request
		# Each parameter is in a new multipart boundary section
		# We don't do much with os/os version/source yet
		$Body = (
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="api_key"',
			"",
			$key,
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="filename"',
			"",
			$fileName,
            "------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="password"',
			"",
			$password,
            "------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="tags"',
			"",
			"LR-SmartResponse",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="os"',
			"",
			"",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="osver"',
			"",
			"",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="source"',
			"",
			"",

			# This is the file itself
			"------------MULTIPARTBOUNDARY_`$",
			("Content-Disposition: form-data; name=`"sample`"; filename=`"$($fileName)`""),
			("Content-Type: `"$($fileType)`""),
			"",
			$fileContent,
			"------------MULTIPARTBOUNDARY_`$--",
			""
		) -join "`r`n"

		# Tell TG what the content-type is and what the boundary looks like
		$ContentType = 'multipart/form-data; boundary=----------MULTIPARTBOUNDARY_$'

		$Uri = "https://panacea.threatgrid.com/api/v2/samples"
		$Uri
		try {
			# Call ThreatGRID
			$Response = Invoke-RestMethod -Uri $Uri -Headers $api_headers -method POST -Body $Body -ContentType $ContentType
            Start-Sleep -Seconds 30 #Wait

			#$Response | Select-Object -ExpandProperty data

            #Remove-Item -Path C:\temp\proc\ -Recurse
		}
		catch {
			#return $null
		}
}
