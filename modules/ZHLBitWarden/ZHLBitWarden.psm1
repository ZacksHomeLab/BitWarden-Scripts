function New-ZHLBWBackupName {
<#
.Synopsis
    This function generates a backup name for your BitWarden backup.
.DESCRIPTION
    This function generates a backup name for your BitWarden backup.
.PARAMETER Directory
    Provide the directory for where the file will reside (if applicable)
.EXAMPLE
    New-ZHLBWBackupName
    
    Generate a Backup name for your BitWarden Backup. (Example name: BitWardenBackup-2022-01-13_20-33-47.tar)
.EXAMPLE
    New-ZHLBWBackupName -Directory '/tmp/'

    This example would generate a directory + file name such as '/tmp/BitWardenBackup-2022-01-13_20-33-47.tar'.
.INPUTS
    System.string
.OUTPUTS
    System.string
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-path -Path $_})]
        [string]$Directory
    )
    begin {
        $FULL_FILE_NAME = $null
    }

    process {
        # If a directory was given, make sure teh directory doesn't have extra '/'s in its name.
        if ($PSBoundParameters.containskey('Directory')) {

            # Remove the extra '/' if applicable
            if ($Directory[-1] -eq '/') {
                $Directory = $Directory.Substring(0,$Directory.Length-1)
            }
            # Example name: /tmp/Extract-BitWardenBackup-2023-01-13_20-55-23
            $FULL_FILE_NAME = $Directory + "/" + "BitWardenBackup-$((Get-Date).toString('yyyy-MM-dd_HH-mm-ss')).tar"
        } else {
            # Directory wasn't given
            $FULL_FILE_NAME = "BitWardenBackup-$((Get-Date).toString('yyyy-MM-dd_HH-mm-ss')).tar"
        }
    }

    end {
        return $FULL_FILE_NAME
    }
}

function New-ZHLBWBackupDecryptionName {
<#
.Synopsis
    This function will generate a file name which will be used for decrypting the backup archive.
.DESCRIPTION
    This function will generate a file name which will be used for decrypting the backup archive. Example Name: /tmp/Decrypt-BitWardenBackup-2023-01-13_20-55-23
.PARAMETER Directory
    Provide the directory for where the file will reside (if applicable)
.EXAMPLE
    New-ZHLBWBackupDecryptionName
    
    This example would generate a file name such as /tmp/Decrypt-BitWardenBackup-2023-01-13_20-55-23
.EXAMPLE
    New-ZHLBWBackupDecryptionName -Directory '/tmp/'

    This example would generate a directory + file name such as '/tmp/Decrypt-BitWardenBackup-2023-01-13_20-55-23'.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>

    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-path -Path $_})]
        [string]$Directory
    )
    begin {
        $FULL_FILE_NAME = $null
    }

    process {
        # If a directory was given, make sure teh directory doesn't have extra '/'s in its name.
        if ($PSBoundParameters.containskey('Directory')) {

            # Remove the extra '/' if applicable
            if ($Directory[-1] -eq '/') {
                $Directory = $Directory.Substring(0,$Directory.Length-1)
            }
            # Example name: /tmp/Extract-BitWardenBackup-2023-01-13_20-55-23
            $FULL_FILE_NAME = $Directory + "/" + "Decrypt-BitWardenBackup-$((Get-Date).toString('yyyy-MM-dd_HH-mm-ss')).tar"
        } else {
            # Directory wasn't given
            $FULL_FILE_NAME = "Decrypt-BitWardenBackup-$((Get-Date).toString('yyyy-MM-dd_HH-mm-ss')).tar"
        }
    }

    end {
        return $FULL_FILE_NAME
    }
}

function New-ZHLBWBackupExtractionName {
<#
.Synopsis
    This function will generate a directory name which will be used for extracting the backup archive.
.DESCRIPTION
    This function will generate a directory name which will be used for extracting the backup archive. Example Name: /tmp/Extract-BitWardenBackup-2023-01-13_20-55-23
.PARAMETER Directory
    Provide the directory for where the file will reside (if applicable)
.EXAMPLE
    New-ZHLBWBackupExtractionName
    
    This example would generate a directory name such as Extract-BitWardenBackup-2023-01-13_20-55-23
.EXAMPLE
    New-ZHLBWBackupExtractionName -Directory '/tmp/'

    This example would generate a directory + file name such as '/tmp/Extract-BitWardenBackup-2023-01-13_20-55-23'.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-path -Path $_})]
        [string]$Directory
    )
    begin {
        $FULL_FILE_NAME = $null
    }
    process {
        if ($PSBoundParameters.containskey('Directory')) {

            # Remove the extra '/' if applicable
            if ($Directory[-1] -eq '/') {
                $Directory = $Directory.Substring(0,$Directory.Length-1)
            }
            # Example name: /tmp/Extract-BitWardenBackup-2023-01-13_20-55-23
            $FULL_FILE_NAME = $Directory + "/" + "Extract-BitWardenBackup-$((Get-Date).toString('yyyy-MM-dd_HH-mm-ss'))"
        } else {
            # Directory wasn't given
            $FULL_FILE_NAME = "Extract-BitWardenBackup-$((Get-Date).toString('yyyy-MM-dd_HH-mm-ss'))"
        }
    }
    end {
        return $FULL_FILE_NAME
    }
}

function Backup-ZHLBWBitWarden {
<#
.Synopsis
    This function generates a BitWarden Backup.
.DESCRIPTION
    This function will create a backup file name if one isn't provided and utilizes tar to generate said backup of the provided Items.
.PARAMETER Items
    The item, directory, or directories of items that you would like added to the tar archive.
.PARAMETER BackupName
    Provide a BackupName alternative. If you do not provide one, a backup name will be generated for you.
.EXAMPLE
    Backup-ZHLBWBitWarden -Items "/opt/bitwarden/bwdata/env", "/opt/bitwarden/bwdata/core/attachments", "/opt/bitwarden/bwdata/mssql/data" -BackupName (New-ZHLBWBackupName)
    
    Create a tar archival of the provided items with a generated backup name of BitWardenBackup-2022-01-13_20-33-47.tar
.INPUTS
    None
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Items,

        [parameter(Mandatory,
            Position=1,
            HelpMessage="Enter the name of your backup. It must end with .tar")]
            [ValidateScript({$_ -match "^(.*)\.tar$"})]
        [string]$BackupName
    )

    process {
        Write-Verbose "Backup-ZHLBWBitWarden: Creating backup $BackupName..."

        # Begin Backup Process
        foreach ($Item in $Items) {

            # Check if the archive already exists as we just want to add onto the archive if it does exist
            if (-not (Test-Path -Path $BackupName)) {
                tar -cf $BackupName $Item
            } else {
                tar -rf $BackupName $Item
            }
        }

        # Verify the backup was created
        if (-not (Test-Path -Path $BackupName)) {
            Write-Error "Backup-ZHLBWBitWarden: Did not create backup $BackupName..."
            break
        }
    }
}

function Remove-ZHLBWBackups {
<#
.Synopsis
    This function will remove encrypted backups that are past a given time frame.
.DESCRIPTION
    This function will gather all the encrypted items with a '.gpg' extension in the provided BackupLocation and see which items are past the provided 'Days' time frame. It will then delete said items past the provided threshold.
.PARAMETER Days
    Provide the day amount in which you want to retain backups. For example, if you provide the number 14, backups older than 14 days wil be deleted.
.PARAMETER BackupLocation
    The location that houses your BitWarden backups.
.EXAMPLE
    Remove-ZHLBWBackups -Days 14 -BackupLocation '/backups'
    
    Remove backups older than 14 days within the location '/backups'.
.INPUTS
    None
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [ValidateRange(1, 365)]
        [int]$Days,

        [Parameter(Mandatory,
            Position=1,
            ValueFromPipeline)]
        [ValidateScript({Test-Path -Path $_})]
        [string]$BackupLocation
    )

    begin {
        # Backups older than this date will get deleted
        $RetentionDate = (Get-Date).AddDays(-$Days)

        # Retrieve the full path of the old backups
        $OutDatedBackups = Get-ChildItem -Path $BackupLocation -ErrorAction silentlyContinue | Where-Object {$_.Name -like "*.gpg" -and $_.LastWriteTime -lt $RetentionDate} | Select-Object -ExpandProperty FullName
    }

    process {

        if ($null -ne $OutDatedBackups -and $OutDatedBackups -ne "") {
            # Creating a loop so I can log each deletion
            foreach($Backup in $OutdatedBackups) {
                Write-Output "Remove-ZHLBWBackups: Attempting to delete backup $Backup."
                Remove-Item -Path $Backup -Force
            }
        } else {
            Write-Output "Remove-ZHLBWBackups: There aren't any backups within $BackupLocation older than $(($RetentionDate).toString('yyyy-MM-dd'))."
        }
    }
}

function Lock-ZHLBWBackup {
<#
.Synopsis
    This function will encrypt the provided backup file with the provided password phrase or password file.
.DESCRIPTION
    This function will encrypt the provided backup file with the provided password phrase or password file.
.PARAMETER BackupFile
    The location of the BitWarden backup.
.PARAMETER PasswordFile
    The location of the password file to encrypt said backup.
.PARAMETER PasswordPhrase
    The password phase that'll encrypt said backup.
.EXAMPLE
    Lock-ZHLBWBackup -BackupFile '/backups/BitWardenBackup-2022-01-13_20-33-47.tar' -PasswordFile '/opt/bitwarden/password_file'
    
    Encrypt the provided backup file with the provided password file.
.EXAMPLE
    Lock-ZHLBWBackup -BackupFile '/backups/BitWardenBackup-2022-01-13_20-33-47.tar' -PasswordPhrase ('PASSWORD_HERE' | ConvertTo-SecureString -AsPlainText)

    Encrypt the provided backup file with the provided password phrase.
.INPUTS
    System.String
    System.Security.SecureString
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$BackupFile,

        [parameter(Mandatory,
            Position=1,
            ValueFromPipelineByPropertyName,
            ParameterSetName='PasswordFile')]
            [ValidateScript({Test-Path -path $_})]
        [string]$PasswordFile,

        [parameter(Mandatory,
            Position=1,
            ValueFromPipelineByPropertyName,
            ParameterSetName='PasswordPhrase')]
            [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$PasswordPhrase
    )

    begin {
        # Encrypted Backup File Location
        if ($BackupFile -notlike '*.gpg') {
            $ENCRYPTED_BACKUP_NAME = "$($BackupFile).gpg"
        } else {
            $ENCRYPTED_BACKUP_NAME = $BackupFile
        }
    }

    process {
        # Encrypt the backup with a Password File or Password Phrase
        if ($PSCmdlet.ParameterSetName -eq 'PasswordFile') {
            Write-Verbose "Lock-ZHLBWBackup: Attempting to encrypt backup $BackupFile with Password File $PasswordFile..."
            Get-Content -Path $PasswordFile | gpg --batch -c --passphrase-fd 0 $BackupFile
        } elseif ($PSCmdlet.ParameterSetName -eq 'PasswordPhrase') {
            Write-Verbose "Lock-ZHLBWBackup: Attempting to encrypt backup $BackupFile with a provided Password phrase..."
            ConvertFrom-SecureString -SecureString $PasswordPhrase -AsPlainText | gpg --batch -c --passphrase-fd 0 $BackupFile
        }
        
        # Test if encryption was successful
        if (-not (Test-Path -Path $ENCRYPTED_BACKUP_NAME)) {
            Write-Error "Lock-ZHLBWBackup: Could not find encrypted backup $ENCRYPTED_BACKUP_NAME"
            break
        }
    }
}

function Unlock-ZHLBWBackup {
<#
.Synopsis
    This function will decrypt a provided BitWarden Backup file.
.DESCRIPTION
    This function will decrypt the provided backup file (must be file format .gpg) with the provided password phrase or password file.
.PARAMETER BackupFile
    The location of the BitWarden backup.
.PARAMETER PasswordFile
    The location of the password file to encrypt said backup.
.PARAMETER PasswordPhrase
    The password phase that'll encrypt said backup.
.PARAMETER DecryptLocation
    The full path & file name of the decrypted backup (e.g., /tmp/Decrypt-BitWardenBackup-2023-01-13_20-55-23)
.EXAMPLE
    UnLock-ZHLBWBackup -BackupFile '/backups/BitWardenBackup-2022-01-13_20-33-47.tar' -PasswordFile '/opt/bitwarden/password_file'
    
    Decrypt the provided backup file with the provided password file.
.EXAMPLE
    UnLock-ZHLBWBackup -BackupFile '/backups/BitWardenBackup-2022-01-13_20-33-47.tar' -PasswordPhrase ('PASSWORD_HERE' | ConvertTo-SecureString -AsPlainText) -DecryptLocation (New-ZHLBWBackupDecryptionName)

    Decrypt the provided backup file with the provided password phrase.
.INPUTS
    System.String
    System.Security.SecureString
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0,
            ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-Path -Path $_})]
        [string]$BackupFile,

        [parameter(Mandatory,
            ParameterSetName='PasswordFile',
            Position=1,
            ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-Path -Path $_})]
        [string]$PasswordFile,

        [parameter(Mandatory,
            ParameterSetName='Passwordphrase',
            Position=1,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$Passphrase,

        [parameter(Mandatory=$false,
            Position=2,
            ValueFromPipelineByPropertyName,
            HelpMessage="Enter the full path and file name for the decrypted backup. Must end with .tar")]
            [ValidateScript({$_ -match "^(.*)\.tar$"})]
        [string]$DecryptLocation
    )

    begin {
        # If a location wasn't given, create one
        if (-not $PSBoundParameters.containskey('DecryptLocation')) {
            $DECRYPT_LOCATION = New-ZHLBWBackupDecryptionName
        } else {
            $DECRYPT_LOCATION = $DecryptLocation
        }
    }

    process {

        Write-Verbose "Unlock-ZHLBWBackup: Decrypted File Location: $DECRYPT_LOCATION"

        # Decrypt the backup with provided password file or passphrase
        if ($PSCmdlet.ParameterSetName -eq "PasswordFile") {
            Write-Verbose "Unlock-ZHLBWBackup: Attempting to decrypt backup file $BackupFile with Password file $PasswordFile."
            gpg --batch --passphrase-file $PasswordFile --output $DECRYPT_LOCATION --decrypt $BackupFile
        } elseif ($PSCmdlet.ParameterSetName -eq "Passwordphrase") {
            Write-Verbose "Unlock-ZHLBWBackup: Attempting to decrypt backup file $BackupFile with a given passphrase."
            gpg --batch --passphrase $Passphrase --output $DECRYPT_LOCATION --decrypt $BackupFile
        }

        # Verify if the Decrypted backup was created
        if (-not (Test-Path -Path $DECRYPT_LOCATION)) {
            Write-Warning "Unlock-ZHLBWBackup: Failed to decrypt backup $BackupFile."
            break
        }

        Write-Verbose "Unlock-ZHLBWBackup: Successfully decrypted backup $BackupFile. File is located at $DECRYPT_LOCATION"
    }
}
function Get-ZHLBWExtractedItems {
<#
.Synopsis
    This function will extract contents of a BitWarden Archive into an extraction location.
.DESCRIPTION
    This function will extract contents of a BitWarden Archive into an extraction location.
.PARAMETER ExtractLocation
    The location that holds the extracted BItWarden Backup items.
.EXAMPLE
    Get-ZHLBWExtractedItems -ExtractLocation '/opt/bitwarden-2022-01-13_20-33-47'
    
    The above will gather the contents within '/opt/bitwarden-2022-01-13_20-33-47'.
.INPUTS
    System.String
.OUTPUTS
    System.Object[]
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$ExtractLocation
    )
    
    end {
        return (Get-ChildItem -Path $ExtractLocation -Recurse)
    }
}
function Expand-ZHLBWBackup {
<#
.Synopsis
    This function will extract contents of a BitWarden Archive into an extraction location.
.DESCRIPTION
    This function will extract contents of a BitWarden Archive into an extraction location.
.PARAMETER ArchiveFile
    The location of the BitWarden Backup Archive file.
.PARAMETER ExtractLocation
    The location to store said extracted items.
.EXAMPLE
    Expand-ZHLBWBackup -ArchiveFile '/backups/BitWardenBackup-2022-01-13_20-33-47.tar'
    
    The above will extract the contents of BitWardenBackup-2022-01-13_20-33-47.tar into a generated Extraction Directory.
.EXAMPLE
    Expand-ZHLBWBackup -ArchiveFile '/backups/BitWardenBackup-2022-01-13_20-33-47.tar' -ExtractLocation '/opt/bitwarden-2022-01-13_20-33-47'
    
    The above will extract the contents of BitWardenBackup-2022-01-13_20-33-47.tar into directory /opt/bitwarden-2022-01-13_20-33-47
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$ArchiveFile,

        [parameter(Mandatory,
            Position=1,
            ValueFromPipelineByPropertyName)]
        [string]$ExtractLocation
    )

    begin {

        # If an Extract location wasn't given, create one
        # As this has to be a directory, we'll need to check for trailing '/'.
        if ($ExtractLocation[-1] -eq '/' -or $ExtractLocation[-1] -eq '\') {
            $ExtractLocation = $ExtractLocation.Substring(0,$ExtractLocation.Length-1)
        }
        $EXTRACT_DIRECTORY = $ExtractLocation
    }

    process {
        # If EXTRACT_DIRECTORY doesn't exist, create it
        if (-not (Test-Path -Path $EXTRACT_DIRECTORY)) {
            Write-Verbose "Expand-ZHLBWBackup: Attempting to create location $EXTRACT_DIRECTORY."
            New-Item -Path $EXTRACT_DIRECTORY -ItemType Directory -Force -ErrorAction Stop
        }

        # Extract Backup to Extract Location
        Write-Verbose "Expand-ZHLBWBackup: Attempting to extract $ArchiveFile to extract location $EXTRACT_DIRECTORY"
        tar --extract -f $ArchiveFile --directory $EXTRACT_DIRECTORY

        # Verify if we have any items extracted
        if ($LastExitCode -ne 0) {
            Write-Error "Expand-ZHLBWBackup: Doesn't appear the extraction succeeded."
            break
        }
    }
}

function Restore-ZHLBWBackup {
<#
.Synopsis
    This function will attempt to restore BItWarden Items.
.DESCRIPTION
    This function will attempt to restore the provided BitWarden Items to their appropriate location.
.PARAMETER ExtractedItems
    The extracted BitWarden items from an extracted backup.
.PARAMETER ExtractLocation
    The location where the extracted items resided. This is specifically used to change the file path of the extracted item(s).
.EXAMPLE
    Restore-ZHLBWBackup -ExtractedItems (Get-ChildItem -Path $ExtractLocation -Recurse) -ExtractLocation '/tmp/Extract-BitWardenBackup-2023-01-13_20-55-23'
    
    The above will attempt to restore contents of our extracted BitWarden items.
.INPUTS
    System.Object[]
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
        [System.Object[]]$ExtractedItems,

        [parameter(Mandatory,
            Position=1,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$ExtractLocation
    )

    begin {
        $Destination = $null
    }

    process {
        foreach ($Item in $ExtractedItems) {
            # if item isn't a directory, proceed
            if ($item -isnot [System.IO.DirectoryInfo]) {
                # Remove the unimportant parent directories from the destination (e.g., /tmp/BitwardenBackup-x-x-)
                $Destination = (($Item | Select-Object -ExpandProperty FullName).Replace($ExtractLocation,''))

                Write-Verbose "Restore-ZHLBWBackup: Attempting to restore item $item at location $Destination."

                # Attempt to replace data
                try {
                    Copy-Item -Path $($Item.Fullname) -Destination $Destination -Force -ErrorAction Stop
                } catch {
                    Throw "Restore-ZHLBWBackup: Failed to copy $Item to destination $Destination because of error $_."
                }
            }
        }
    }
}

function Stop-ZHLBWBitwarden {
<#
.Synopsis
    This function will attempt to stop the BitWarden service.
.DESCRIPTION
    This function will attempt to stop the BitWarden service. If it fails to do so within 60 seconds, it'll error.
.PARAMETER ScriptLocation
    The path to BitWarden's Service Script.
.EXAMPLE
    Stop-ZHLBWBitwarden -ScriptLocation '/opt/bitwarden/bitwarden.sh'
    
    The above will attempt to stop BitWarden via Service Script.
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$ScriptLocation
    )
    begin {

        # If Bitwarden is running, this process should exist.
        $SQLProcess = Get-Process -Name sqlservr -ErrorAction SilentlyContinue
        $Count = 0
    }
    
    process {

        if ($null -ne $SQLProcess) {
            Write-Verbose "Stop-ZHLBWBitwarden: Attempting to stop Bitwarden with script file $ScriptLocation."
            bash $ScriptLocation stop
            do {
                Start-Sleep -Seconds 2
                $SQLProcess = Get-Process -Name sqlservr -ErrorAction SilentlyContinue
                if ($null -ne $SQLProcess -or $SQLProcess -ne "") {
                    $Count += 1
                }
            } until (($null -eq $SQLProcess) -or $Count -ge 30)
            
            # Stop the script if Bitwarden hasn't stopped in over 60 seconds
            if ($null -ne $SQLProcess -and $Count -ge 30) {
                Throw "Stop-ZHLBWBitwarden: Failed to stop Bitwarden, stopping."
            }
            
            Write-Verbose "Stop-ZHLBWBitwarden: Successfully stopped Bitwarden."
        } else {
            Write-Verbose "Stop-ZHLBWBitWArden: BitWarden was already stopped."
        }
    }
}

function Start-ZHLBWBitwarden {
<#
.Synopsis
    This function will attempt to start the BitWarden service.
.DESCRIPTION
    This function will attempt to start the BitWarden service. If it fails to do so within 60 seconds, it'll error.
.PARAMETER ScriptLocation
    The path to BitWarden's Service Script.
.EXAMPLE
    Start-ZHLBWBitwarden -ScriptLocation '/opt/bitwarden/bitwarden.sh'
    
    The above will attempt to start BitWarden via Service Script.
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$ScriptLocation
    )
    begin {

        # If Bitwarden is running, this process should exist.
        $SQLProcess = Get-Process -Name sqlservr -ErrorAction SilentlyContinue
        $Count = 0
    }
    
    process {
        if ($null -eq $SQLProcess) {
            Write-Verbose "Start-ZHLBWBitwarden: Attempting to start Bitwarden with script file $ScriptLocation."
                bash $ScriptLocation start
                do {
                    Start-Sleep -Seconds 2
                    $SQLProcess = Get-Process -Name sqlservr -ErrorAction SilentlyContinue
                    if ($null -eq $SQLProcess -or $SQLProcess -eq "") {
                        $Count += 1
                    }
                } until (($null -ne $SQLProcess) -or $Count -ge 30)
                
                # Stop the script if Bitwarden hasn't stopped in over 60 seconds
                if ($null -eq $SQLProcess -and $Count -ge 30) {
                    Throw "Start-ZHLBWBitwarden: Failed to start Bitwarden, stopping."
                }
                Write-Verbose "Start-ZHLBWBitwarden: Successfully started Bitwarden."
        } else {
            Write-Verbose "Start-ZHLBWBitwarden: Bitwarden is already running, no need to start."
        }
    }
}

function Restart-ZHLBWBitWarden {
<#
.Synopsis
    This function will attempt to restart the BitWarden service.
.DESCRIPTION
    This function will attempt to restart the BitWarden service. If it fails to do so within 60 seconds, it'll error.
.PARAMETER ScriptLocation
    The path to BitWarden's Service Script.
.EXAMPLE
    Restart-ZHLBWBitWarden -ScriptLocation '/opt/bitwarden/bitwarden.sh'
    
    The above will attempt to restart BitWarden via Service Script.
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$ScriptLocation
    )

    PROCESS {
        
        try {
            Write-Verbose "Restart-ZHLBWBitWarden: Attempting to stop BitWarden..."
            Stop-ZHLBWBitwarden -ScriptLocation $ScriptLocation -ErrorAction Stop
        } catch {
            Throw "Restart-ZHLBWBitWarden: Failed to stop BitWarden due to $_"
        }
        
        try {
            Write-Verbose "Restart-ZHLBWBitWarden: BitWarden successfully Stopped, attempting to start BitWarden..."
            Start-ZHLBWBitwarden -ScriptLocation $ScriptLocation -ErrorAction Stop
        } catch {
            Throw "Restart-ZHLBWBitWarden: Failed to start BitWarden due to $_"
        }
    }
}

function Update-ZHLBWBitWardenScripts {
<#
.Synopsis
    This function will replace the BitWarden Scripts with the downloaded variants.
.DESCRIPTION
    This function will replace the current BitWarden Script with the New Variant and save the current version to an 'OldScript' location.
.PARAMETER CurrentScript
    The path to the current BitWarden Script.
.PARAMETER NewScript
    The path to the new BitWarden Script.
.PARAMETER OldScript
    The path to save the current script to before we replace it with the new one.
.EXAMPLE
    Update-ZHLBWBitWardenScripts -CurrentScript '/opt/bitwarden/bitwarden.sh' -NewScript '/opt/bitwarden-2023-01-13-24-55/bitwarden.sh' -OldScript '/opt/bitwarden-2023-01-13-24-55/bitwarden.sh.old'
    
    The above will copy CurrentScript to OldScript. Then, copy NewScript to CurrentScript.
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory, 
            Position=0,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$CurrentScript,

        [parameter(Mandatory, 
            Position=1)]
        [string]$NewScript,

        [parameter(Mandatory, 
            Position=2)]
        [string]$OldScript
    )
    PROCESS {
        
        try {
            Write-Verbose "Update-ZHLBWBitWardenScript: Attempting to move $CurrentScript to $OldScript."
            Copy-Item -Path $CurrentScript -Destination $OldScript -Force -ErrorAction Stop
        } catch {
            Throw "Update-ZHLBWBitWardenScript: Failed replacing $CurrentScript with $OldScript due to $_"
        }
        
        try {
            Write-Verbose "Update-ZHLBWBitWardenScript: Attempting to move $NewScript to $CurrentScript."
            Copy-Item -Path $NewScript -Destination $CurrentScript -Force -ErrorAction Stop
        } catch {
            Throw "Update-ZHLBWBitWardenScript: Failed replacing $CurrentScript with $NewScript due to $_"
        }

        Write-Verbose "Update-ZHLBWBitWardenScript: Successfully replace $CurrentScript with $NewScript. Old Script is saved at $OldScript."
    }
}


function Install-ZHLBWBitWardenScripts {
<#
.Synopsis
    This function will Download the BitWarden Script.
.DESCRIPTION
    This function will Download the BitWarden Script and store it at the provided OutFile path.
.PARAMETER URL
    The URL of the BitWarden script to be downloaded.
.PARAMETER OutFile
    The path where the downloaded script will reside.
.EXAMPLE
    Install-ZHLBWBitWardenScripts -URL (Get-ZHLBWRunScriptURL -CurrentRunScript '/opt/bitwarden/bwdata/scripts/run.sh') -OutFile '/opt/bitwarden-2023-01-13-24-55/run.sh'
    
    The above will download the BitWarden Run Script and store it in the above provided OutFile path.
.EXAMPLE
    Install-ZHLBWBitWardenScripts -URL (Get-ZHLBWScriptURL -CurrentScript '/opt/bitwarden/bitwarden.sh') -OutFile '/opt/bitwarden-2023-01-13-24-55/bitwarden.sh'
    
    The above will download the BitWarden Script and store it in the above provided OutFile path.
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
            [ValidateNotNullOrEmpty()]
        [string]$URL,

        [parameter(Mandatory,
            Position=1)]
            [ValidateNotNullOrEmpty()]
        [string]$OutFile
    )

    PROCESS {
        try {
            Write-Verbose "Install-ZHLBWBitWardenScript: Attempt to download BitWarden's script from $URL to location $OutFile..."
            Invoke-WebRequest -Uri $URL -OutFile $OutFile -ErrorAction Stop
        } catch {
            Throw "Install-ZHLBWBitWardenScript: Did not successfully download the BitWarden Script due to $_"
        }
    }
}

function Update-ZHLBWScriptPermissions {
<#
.Synopsis
    This function will set the appropriate permissions for the provided BitWarden script file.
.DESCRIPTION
    This function will set the appropriate permissions for the provided BitWarden script file.
.PARAMETER Path
    The Path to BitWarden's script.
.EXAMPLE
    Update-ZHLBWScriptPermissions -Path '/opt/bitwarden-2022-12-25-10-45/bitwarden.sh'
    
    The above will update the permissions to the above downloaded bitwarden.sh file.
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$Path
    )

    BEGIN {
        $CORRECT_USER_PERMISSIONS = "bitwarden"
        $CORRECT_GROUP_PERMISSIONS = "docker"
        $CORRECT_Unix_MODE = "-rwxr--r--"
        $SCRIPT_FILE = Get-Item -Path $Path
    }

    PROCESS {

        # Set the appropriate user/group permissions for the script file.
        if ($SCRIPT_FILE.user -ne $CORRECT_USER_PERMISSIONS -and $SCRIPT_FILE.group -ne $CORRECT_GROUP_PERMISSIONS) {
            Write-Verbose "Update-ZHLBWScriptPermissions: Updating script user and group ownership to $($CORRECT_USER_PERMISSIONS):$($CORRECT_GROUP_PERMISSIONS)"
            chown "$($CORRECT_USER_PERMISSIONS):$($CORRECT_GROUP_PERMISSIONS)" $($SCRIPT_FILE).FullName
        } elseif ($SCRIPT_FILE.group -ne $CORRECT_GROUP_PERMISSIONS) {
            Write-Verbose "Update-ZHLBWScriptPermissions: Updating script group ownership to $($CORRECT_GROUP_PERMISSIONS)"
            chown ":$($CORRECT_GROUP_PERMISSIONS)" $($SCRIPT_FILE).FullName
        } elseif ($SCRIPT_FILE.User -ne $CORRECT_USER_PERMISSIONS) {
            Write-Verbose "Update-ZHLBWScriptPermissions: Updating script user ownership to $($CORRECT_USER_PERMISSIONS)"
            chown $($CORRECT_USER_PERMISSIONS) $($SCRIPT_FILE).FullName
        }


        # Set the appropriate file permissions for the script
        if ($SCRIPT_FILE.unixmode -ne $CORRECT_Unix_MODE) {
            Write-Verbose "Update-ZHLBWScriptPermissions: Updating script UnixMode permissions to $($CORRECT_Unix_MODE)"
            chmod u+x $($SCRIPT_FILE).FullName
        }

        # Validate our changes were successful
        Write-Verbose "Update-ZHLBWScriptPermissions: Validate changes to current script file.."
        $NewPermissions = Get-Item -Path $Path
        if ($NewPermissions.user -ne $CORRECT_USER_PERMISSIONS -and $NewPermissions.group -ne $CORRECT_GROUP_PERMISSIONS -and $NewPermissions.UnixMode -ne $CORRECT_Unix_MODE) {
            Throw "Update-ZHLBWScriptPermissions: The provided group, user, and file permissions were not successfully applied to $Path."
        }
    }
}

function Get-ZHLBWWebID {
<#
.Synopsis
    This function will retrieve BitWarden's current Web ID.
.DESCRIPTION
    This function will retrieve BitWarden's current Web ID by reading the docker file and using said info on the Docker Image.
.PARAMETER DockerFile
    The Path to BitWarden's docker file.
.EXAMPLE
    Get-ZHLBWWebID -DockerFile '/opt/bitwarden/bwdata/docker/docker-compose.yml'
    
    The above will retrieve BitWarden's Web ID using said provided docker file.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-path -Path $_})]
        [string]$DockerFile
    )
    
    BEGIN {
        $WEB_ID = $null
    }
    PROCESS {
        # Retrieve WEB_ID
        Write-Verbose "Get-ZHLBWWebID: Attempting to retrieve Web ID from Docker file $DockerFile..."
        $WEB_ID = docker compose --file $DockerFile ps -q web
        $WEB_ID = docker inspect --format='{{.Config.Image}}:' $WEB_ID
    }
    END {
        return $WEB_ID
    }
}

function Get-ZHLBWCoreID {
<#
.Synopsis
    This function will retrieve BitWarden's current Core ID.
.DESCRIPTION
    This function will retrieve BitWarden's current Core ID by reading the docker file and using said info on the Docker Image.
.PARAMETER DockerFile
    The Path to BitWarden's docker file.
.EXAMPLE
    Get-ZHLBWCoreID -DockerFile '/opt/bitwarden/bwdata/docker/docker-compose.yml'
    
    The above will retrieve BitWarden's Core ID using said provided docker file.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-path -Path $_})]
        [string]$DockerFile
    )
    
    BEGIN {
        $CORE_ID = $null
    }

    PROCESS {
        Write-Verbose "Get-ZHLBWCoreID: Attempting to retrieve Core ID from Docker file $DockerFile..."
        $CORE_ID = docker compose --file $DockerFile ps -q admin
        $CORE_ID = docker inspect --format='{{.Config.Image}}:' $CORE_ID
    }
    end {
        return $CORE_ID
    }
}

function Get-ZHLBWKeyConnectorStatus {
<#
.Synopsis
    This function will retrieve BitWarden's current Key Connector Status.
.DESCRIPTION
    This function will retrieve BitWarden's current Key Connector Status by reading BitWarden's Configuration file.
.PARAMETER DockerFile
    The Path to BitWarden's configuration file.
.EXAMPLE
    Get-ZHLBWKeyConnectorStatus -Config '/opt/bitwarden/bwdata/config.yml'
    
    The above will retrieve BitWarden's Key Connector Status using said provided docker file.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-path -Path $_})]
        [string]$ConfigFile
    )
    END {
        return (Select-String -Path $ConfigFile -Pattern "enable_key_connector").toString().split(':')[-1].trim()
    }
}
function Get-ZHLBWKeyConnectorID {
<#
.Synopsis
    This function will retrieve BitWarden's current Key Connector ID.
.DESCRIPTION
    This function will retrieve BitWarden's current Key Connector ID by reading the docker file and using said info on the Docker Image.
.PARAMETER DockerFile
    The Path to BitWarden's docker file.
.EXAMPLE
    Get-ZHLBWKeyConnectorID -DockerFile '/opt/bitwarden/bwdata/docker/docker-compose.yml'
    
    The above will retrieve BitWarden's Key Connector ID using said provided docker file.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-path -Path $_})]
        [string]$DockerFile
    )
    
    BEGIN {
        $KEY_CONNECTOR_ID = $null
    }

    PROCESS {
        Write-Verbose "Get-ZHLBWKeyConnectorID: Attempting to retrieve Key Connector ID from Docker file $DockerFile..."
        $KEY_CONNECTOR_ID = docker compose --file $DockerFile ps -q key-connector
        $KEY_CONNECTOR_ID = docker inspect --format='{{.Config.Image}}:' $KEY_CONNECTOR_ID
    }
    END {
        return $KEY_CONNECTOR_ID
    }
}

function Get-ZHLBWRunScriptURL {
<#
.Synopsis
    This function will retrieve the URL for BitWarden's Run Script.
.DESCRIPTION
    This function will retrieve the URL for BitWarden's Run Script by selecting said string from BitWarden's Run File.
.PARAMETER CurrentRunScript
    The Path to BitWarden's Run Script file.
.EXAMPLE
    Get-ZHLBWRunScriptURL -CurrentRunScript '/opt/bitwarden/bwdata/scripts/run.sh'
    
    The above will retrieve the URL for BitWarden's Run Script.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$CurrentRunScript
    )
    
    END {
        return (Select-String -Path $CurrentRunScript -Pattern "RUN_SCRIPT_URL=").toString().split('RUN_SCRIPT_URL=')[-1].Replace('"','')
    }
}

function Get-ZHLBWScriptURL {
<#
.Synopsis
    This function will retrieve the URL for BitWarden's Script.
.DESCRIPTION
    This function will retrieve the URL for BitWarden's Script by selecting said string from BitWarden's Script File.
.PARAMETER CurrentScript
    The Path to BitWarden's Script file.
.EXAMPLE
    Get-ZHLBWRunScriptURL -CurrentScript '/opt/bitwarden/bitwarden.sh'
    
    The above will retrieve the URL for BitWarden's Script.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-Path -Path $_})]
        [string]$CurrentScript
    )
    
    END {
        return (Select-String -Path $CurrentScript -Pattern "BITWARDEN_SCRIPT_URL=").toString().split('BITWARDEN_SCRIPT_URL=')[-1].Replace('"','')
    }
}

function Confirm-ZHLBWUpdate {
<#
.Synopsis
    This function will determine whether BitWarden can be updated or not.
.DESCRIPTION
    This function will query the provided configuration, docker, and newly downloaded files to determine if BitWarden can update.
.PARAMETER ConfigFile
    The Path to BitWarden's configuration file.
.PARAMETER DockerFile
    The Path to BitWarden's Docker file.
.PARAMETER NewScript
    The Path to BitWarden's new script file.
.EXAMPLE
    Confirm-ZHLBWUpdate -ConfigFile '/opt/bitwarden/bitwarden.sh' -DockerFile '/opt/bitwarden/bwdata/docker/docker-compose.yml' -NewScript '/opt/bitwarden-temp/bitwarden.sh'
    
    The above will compare the current version values with the new version values.
.INPUTS
    System.String
.OUTPUTS
    Boolean
#>
	[cmdletbinding()]
	param (
        [parameter(Mandatory,
            Position=0,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({(Test-Path -Path $_) -and ($_ -match "^(.*)\.yml$")})]
		[string]$ConfigFile,

        [parameter(Mandatory,
            Position=1,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({(Test-Path -Path $_) -and ($_ -match "^(.*)\.yml$")})]
        [string]$DockerFile,

        [parameter(Mandatory,
            Position=2)]
            [ValidateScript({(Test-Path -Path $_) -and ($_ -match "^(.*)\.sh$")})]
        [string]$NewScript
	)
	
	BEGIN {

        # Retrieve current version values
        $CURRENT_WEB_ID = (Get-ZHLBWWebID -DockerFile $DockerFile).split(':')[-2]
        $CURRENT_CORE_ID = (Get-ZHLBWCoreID -DockerFile $DockerFile).split(':')[-2]

        # Retrieve the key connector value, should return true or false
		$KEY_CONNECTOR_ENABLED = Get-ZHLBWKeyConnectorStatus -ConfigFile $ConfigFile
        if ($KEY_CONNECTOR_ENABLED -eq 'true') {
            $CURRENT_KEYCONNECTOR_ID = (Get-ZHLBWKeyConnectorID -DockerFile $DockerFile).split(':')[-2]
        }

        # Retrieve the new values from the provided script
        $NEW_CORE_ID = (Select-String -Path $NewScript -Pattern "COREVERSION=").tostring().split('=')[-1].replace('"','')
        $NEW_WEB_ID = (Select-String -Path $NewScript -Pattern "WEBVERSION=").tostring().split('=')[-1].replace('"','')
        if ($KEY_CONNECTOR_ENABLED -eq 'true') {
            $NEW_KEY_CONNECTOR_ID = (Select-String -Path $NewScript -Pattern "KEYCONNECTORVERSION=").tostring().split('=')[-1].replace('"','')
        }
        $UpdateNeeded = $true
	}
	
	PROCESS {

        # Verify the current versions with the new versions
        # TODO: Using Compare-Object would wook nicer
        if ($null -ne $CURRENT_KEYCONNECTOR_ID -and $CURRENT_CORE_ID -match $NEW_CORE_ID -and $CURRENT_WEB_ID -match $NEW_WEB_ID -and $CURRENT_KEYCONNECTOR_ID -match $NEW_KEY_CONNECTOR_ID) {
            Write-Verbose "Confirm-ZHLBWUpdate: We're fully updated."
            $UpdateNeeded = $false

        } elseif ($CURRENT_CORE_ID -match $NEW_CORE_ID -and $CURRENT_WEB_ID -match $NEW_WEB_ID) {
            
            Write-Verbose "Confirm-ZHLBWUpdate: We're fully updated."
            $UpdateNeeded = $false
        } else {
            Write-Verbose "Confirm-ZHLBWUpdate: We can update!"
        }
	}

    END {
        return $UpdateNeeded
    }
}

function Remove-ZHLBWItems {
<#
.Synopsis
    This function will remove our downloaded/created items.
.DESCRIPTION
    This function will remove our downloaded/created items.
.PARAMETER Items
    The array of items to be deleted.
.EXAMPLE
    Remove-ZHLBWItems -Items '/opt/bitwarden-temp'
    
    The above will compare the current version values with the new version values.
.INPUTS
    System.String
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
            [ValidateNotNullOrEmpty()]
        [System.Object[]]$Items
    )

    PROCESS {
        foreach ($Item in $Items) {
            Write-Verbose "Remove-ZHLBWItems: Attempting to remove Item $Item..."
            Remove-Item -Path $Item -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
}

function Send-ZHLBWEmail {
<#
.Synopsis
    This function will send an email.
.DESCRIPTION
    This function will send an email.
.PARAMETER EmailAddresses
    The Email Addresses that'll receive said email.
.PARAMETER From
    The Email Addresses that'll send said email
.PARAMETER SMTPServer
    The SMTP Server that'll be sending said email.
.PARAMETER Subject
    The subject title of said email.
.PARAMETER Body
    The body of said email.
.EXAMPLE
    Send-ZHLBWUpdateEmail -EmailAddresses @("zack@zackshomelab.com", "test@zackshomelab.com") -From 'bitwarden@zackshomelab.com' -SMTPServer 'contoso-com.mail.protection.outlook.com' -Data $EMAIL_DATA
    
    The above will send an update report to zack@zackshomelab.com & test@zackshomelab.com.
.INPUTS
    None
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [string[]]$EmailAddresses,

        [parameter(Mandatory,
            Position=1)]
        [string]$From,

        [parameter(Mandatory,
            Position=2)]
        [string]$SMTPServer,

        [parameter(Mandatory,
            Position=3)]
        [string]$SMTPPort,

        [parameter(Mandatory,
            Position=4)]
        [string]$Subject,

        [parameter(Mandatory,
            Position=5)]
        [string]$body,

        [parameter(Mandatory=$false,
            Position=6,
            ParameterSetName='Creds')]
        [System.Management.Automation.PSCredential]$Creds,

        [parameter(Mandatory,
            Position=7)]
            [ValidateSet("False", "True")]
        [string]$UseSSL
    )

    begin {
        $SMTPPort = $SMTPPort -as [int]

        # Build splat of parameters
        $Params = @{
            To = $EmailAddresses
            From = $From
            Subject = $Subject
            Body = $Body
            BodyAsHtml = $true
            SMTPServer = $SMTPServer
            Port = $SMTPPort
        }
        if ($PSCmdlet.ParameterSetName -eq 'Creds') {
            $Params.add('Credential', $Creds)
        }
        if ($UseSSL -eq 'True') {
            $Params.add('UseSSL', $true)
        }
        $Params.add('ErrorAction', 'Stop')
    }
    process {
        Write-Verbose "Send-ZHLBWEmail: Attempting to send update email..."
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = 'TLS12'
            Send-MailMessage @Params
        } catch {
            Throw "Send-ZHLBWEmail: Failed sending email due to $_"
        }
    }
}


function Send-ZHLBWUpdateEmail {
<#
.Synopsis
    This function will send an email detailing the update that occurred with BitWarden.
.DESCRIPTION
    This function will send an email detailing the update that occurred with BitWarden.
.PARAMETER EmailAddresses
    The Email Addresses that'll receive said email.
.PARAMETER From
    The Email Addresses that'll send said email
.PARAMETER SMTPServer
    The SMTP Server that'll be sending said email.
.PARAMETER Subject
    The subject title of said email.
.PARAMETER Data
    The object of data that is created during the update-bitwarden.ps1 script.
.EXAMPLE
    Send-ZHLBWUpdateEmail -EmailAddresses @("zack@zackshomelab.com", "test@zackshomelab.com") -From 'bitwarden@zackshomelab.com' -SMTPServer 'contoso-com.mail.protection.outlook.com' -Data $EMAIL_DATA
    
    The above will send an update report to zack@zackshomelab.com & test@zackshomelab.com.
.INPUTS
    None
.OUTPUTS
    None
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [string[]]$EmailAddresses,

        [parameter(Mandatory,
            Position=1)]
        [string]$From,

        [parameter(Mandatory,
            Position=2)]
        [string]$SMTPServer,

        [parameter(Mandatory,
            Position=3)]
        [string]$SMTPPort,

        [parameter(Mandatory,
            Position=4)]
        [string]$Subject,

        [parameter(Mandatory,
            Position=5)]
        [System.Object[]]$Data,

        [parameter(Mandatory=$false,
            Position=6,
            ParameterSetName='Creds')]
        [System.Management.Automation.PSCredential]$Creds,

        [parameter(Mandatory,
            Position=7)]
            [ValidateSet("False", "True")]
        [string]$UseSSL
    )
    
    BEGIN {
        $Body = $null  

        $CURRENT_CORE_ID = $Data.CURRENT_CORE_ID
        $LATEST_CORE_ID = $Data.LATEST_CORE_ID
        $CURRENT_WEB_ID = $Data.CURRENT_WEB_ID
        $LATEST_WEB_ID = $Data.LATEST_WEB_ID
        $CURRENT_KEYCONNECTOR_ID = $null
        $LATEST_KEYCONNECTOR_ID = $null
        if ($null -ne $Data.CURRENT_KEYCONNECTOR_ID) {
            $CURRENT_KEYCONNECTOR_ID = $Data.CURRENT_KEYCONNECTOR_ID
            $LATEST_KEYCONNECTOR_ID = $Data.LATEST_KEYCONNECTOR_ID
        }
        $BACKUP_FILE = $Data.BACKUP_FILE

        $SMTPPort = $SMTPPort -as [int]

        # Build splat of parameters
        $Params = @{
            To = $EmailAddresses
            From = $From
            Subject = $Subject
            BodyAsHtml = $true
            SMTPServer = $SMTPServer
            Port = $SMTPPort
        }
        if ($PSCmdlet.ParameterSetName -eq 'Creds') {
            $Params.add('Credential', $Creds)
        }
        if ($UseSSL -eq 'True') {
            $Params.add('UseSSL', $true)
        }
    }

    PROCESS {
        if ($null -ne $CURRENT_KEYCONNECTOR_ID) {
            $body = @"
            <p>Successfully Updated BitWarden from the following verion:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                Old BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$CURRENT_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$CURRENT_WEB_Id</b></td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Key Connector ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$CURRENT_KEYCONNECTOR_ID</b></td>
         </tr>
        </table>
        <p>To the following version:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                New BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$LATEST_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$LATEST_WEB_ID</b></td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Key Connector ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$LATEST_KEYCONNECTOR_ID</b></td>
         </tr>
        </table>
        <p>If there's a bug with this release, perform the following steps to restore BitWarden back to the previous version:</p>
        <ul>
          <li>SSH into your BitWarden Server and run the following commands::</li>
          <ul>
          <li><p>Open PowerShell: <span style="border: 1px solid black">sudo pwsh </span></p></li>
          <li><p>Browse to BitWarden's Directory: <span style="border: 1px solid black">cd /opt/bitwarden </span></p></li>
          <li><p>Restore Backup: <span style="border: 1px solid black">./restore-bitwarden.ps1 -Passwordfile /opt/bitwarden/password_file -BackupFile $BACKUP_FILE</span></p></li>
          </ul>
        </ul>
"@
        } else {
            $body = @"
            <p>Successfully Updated BitWarden from the following verion:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                Old BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$CURRENT_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$CURRENT_WEB_Id</b></td>
         </tr>
        </table>
        <p>To the following version:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                New BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$LATEST_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$LATEST_WEB_ID</b></td>
         </tr>
        </table>
        <p>If there's a bug with this release, perform the following steps to restore BitWarden back to the previous version:</p>
        <ul>
          <li>SSH into your BitWarden Server and run the following commands::</li>
          <ul>
          <li><p>Open PowerShell: <span style="border: 1px solid black">sudo pwsh </span></p></li>
          <li><p>Browse to BitWarden's Directory: <span style="border: 1px solid black">cd /opt/bitwarden </span></p></li>
          <li><p>Restore Backup: <span style="border: 1px solid black">./restore-bitwarden.ps1 -Passwordfile /opt/bitwarden/password_file -BackupFile $BACKUP_FILE</span></p></li>
          </ul>
        </ul>
"@
        }

        try {
            [System.Net.ServicePointManager]::SecurityProtocol = 'TLS12'
            Write-Verbose "Send-ZHLBWUpdateEmail: Attempting to send update email..."
            Send-MailMessage @Params -Body $Body -ErrorAction Stop
        } catch {
            Throw "Send-ZHLBWUpdateEmail: Failed sending email due to $_"
        }
    }
}

function Test-ZHLBWSSLFiles {
<#
.Synopsis
    This function will verify if you have all the necesasry SSL files for renewal.
.DESCRIPTION
    This function will verify a given array of files and verify if said files will exist. The output will be true or false if you have everything.
.PARAMETER Data
    The array of items to be validated.
.EXAMPLE
    $URL = 'bitwarden.zackshomelab.com'
    $ITEMS_TO_VERIFY = @("/etc/letsencrypt/live/$URL/privkey.pem", "/etc/letsencrypt/live/$URL/fullchain.pem", "/etc/letsencrypt/live/$URL/chain.pem")
    
    Test-ZHLBWSSLFiles -Data $ITEMS_TO_VERIFY
    
    The above will verify all the items within ITEMS_TO_VERIFY exist. If they exist, Test-ZHLBWSSLFiles will return True.
.INPUTS
    System.Object[]
.OUTPUTS
    Boolean
#>
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]$Data
    )

    begin {
        $SUCCESS = $true
        $ITEMS_MISSING = @()
        $ITEM_MISSING = $null
        $Item = $null
    }
    process {
        # If any of our items fail validation, set Success to False
        foreach ($Item in $Data) {
            # Verify the item exists
            if (-not (Test-Path -Path $Item)) {
                $ITEMS_MISSING += $Item
            }
        }
        # If ITEMS_MISSING is greater than 0, output what's missing
        if ($ITEMS_MISSING.count -gt 0) {
            Write-Warning "Test-ZHLBWSSLFiles: You're missing the following items:"
            foreach ($ITEM_MISSING in $ITEMS_MISSING) {
                Write-Warning "Test-ZHLBWSSLFiles: Missing $ITEM_MISSING"
            }
            $SUCCESS = $false
        }   
    }
    end {
        return $SUCCESS
    }
}

function Get-ZHLBWEmailSettings {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [ValidateScript({Test-Path -path $_})]
        [string]$GlobalEnv
    )

    begin {
        $EMAIL_DATA = @{}
        # Retrieve the SMTP Server, Port, Username, and Password for the email account.
        $SMTP_SERVER = (select-string -Path $GlobalEnv -Pattern "globalSettings__mail__smtp__host").toString().split('=')[-1]
        $EMAIL_DATA.add('SMTPServer', $SMTP_SERVER)

        $SMTP_PORT = (select-string -Path $GlobalEnv -Pattern "globalSettings__mail__smtp__port").toString().split('=')[-1]
        $EMAIL_DATA.add('SMTPPort', $SMTP_PORT)

        $FROM = (select-string -Path $GlobalEnv -Pattern "globalSettings__mail__smtp__username").toString().split('=')[-1]
        $EMAIL_DATA.add('From', $FROM)

        $PASS = ((select-string -Path $GlobalEnv -Pattern "globalSettings__mail__smtp__password").toString().split('=')[-1]) | ConvertTo-SecureString -AsPlainText -Force -ErrorAction SilentlyContinue
        $EMAIL_DATA.add('Pass', $PASS)

        $UseSSL = (select-string -Path $GlobalEnv -Pattern "globalSettings__mail__smtp__ssl").toString().split('=')[-1]
        $EMAIL_DATA.add('UseSSL', $UseSSL)

        if ($null -ne $PASS) {
            $Creds = New-Object System.Management.Automation.PSCredential ($FROM, $PASS)
            $EMAIL_DATA.add('Creds', $Creds)
        }
    }
    
    end {
        return $EMAIL_DATA
    }
}
#endregion

Export-ModuleMember -Function New-ZHLBWBackupName, New-ZHLBWBackupDecryptionName, New-ZHLBWBackupExtractionName, Backup-ZHLBWBitWarden, Remove-ZHLBWBackups, `
Lock-ZHLBWBackup, Unlock-ZHLBWBackup, Expand-ZHLBWBackup, Restore-ZHLBWBackup, Stop-ZHLBWBitwarden, Start-ZHLBWBitwarden, Restart-ZHLBWBitWarden, Update-ZHLBWBitWardenScripts, `
Install-ZHLBWBitWardenScripts, Update-ZHLBWScriptPermissions, Get-ZHLBWWebID, Get-ZHLBWCoreID, Get-ZHLBWKeyConnectorStatus, Get-ZHLBWKeyConnectorID, Get-ZHLBWRunScriptURL, `
Get-ZHLBWScriptURL, Confirm-ZHLBWUpdate, Remove-ZHLBWItems, Send-ZHLBWEmail, Send-ZHLBWUpdateEmail, Get-ZHLBWExtractedItems, Test-ZHLBWSSLFiles, Get-ZHLBWEmailSettings
