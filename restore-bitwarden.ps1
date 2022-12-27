<#
.Synopsis
    restore-bitwarden.ps1 restores from a Bitwarden backup from an encrypted backup.

.DESCRIPTION
    restore-bitwarden.ps1 restores from an encrypted bitwarden backup, which is decrypted by a given passphrase or password file.

.PARAMETER PasswordFile
    The file that contains the pass phrase used to encrypt the backup.

.PARAMETER Passphrase
    The passphrase used to encrypt the backup file.

.PARAMETER BackupFile
    The full path of the backup file. (e.g., /backups/BitwardenBackup-xx.tar.gpg)

.PARAMETER BitwardenServiceScript
    The location of the bitwarden bash script (default location is /opt/bitwarden/bitwarden.sh)

.PARAMETER LogFile
    The location where the log file will reside (default location is ./restore-bitwarden.log)

.EXAMPLE
    ./restore-bitwarden.ps1 -Passwordfile ./password_file -BackupFile /backups/BitWardenBackup-2022-05-13_00-00-03.tar.gpg

    Restore a backup file with a given password file
#>
[cmdletbinding()]
param (
    [Parameter(Mandatory, 
        ParameterSetName="Passwordfile",
        Position=0)]
    [string]$PasswordFile,

    [Parameter(Mandatory, 
        ParameterSetName="Passphrase",
        Position=0)]
    [string]$Passphrase,

    [Parameter(Mandatory,
        Position=1,
        helpMessage="What's the name and path of the backup file?")]
    [string]$BackupFile,

    [Parameter(Mandatory=$false,
        Position=2,
        helpMessage="What's the name and path of the Bitwarden service script?")]
    [string]$BitwardenServiceScript = '/opt/bitwarden/bitwarden.sh',

    [Parameter(Mandatory=$false)]
    [string]$LogFile = "./Restore-BitWardenBackup.log"
)

#region VARIABLES
$script:LOG_FILE = $LogFile
$script:BITWARDEN_RUN_FILE = "/opt/bitwarden/bwdata/scripts/run.sh"
#endregion

#region FUNCTIONS
function Write-Log
{
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param
    (
        [parameter(Mandatory = $false,
                    Position = 0)]
        [string]$Path = $script:LOG_FILE,
        [Parameter(Position = 1,
                    Mandatory = $true,
                    ParameterSetName = 'Default')]
        [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
        [String]$EntryType,
        [Parameter(Position = 2,
                    Mandatory = $true,
                    ParameterSetName = 'Default')]
        [String]$Message
    )
    
    begin
    {
        
        # Check if the log level an error or an error record was submitted
        if ($PSCmdlet.ParameterSetName -eq 'Default' -and $EntryType -eq 'Error')
        {
            $ErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $Message, 'Unknown', 'NotSpecified', $null
        }
    }
    
    process
    {
        # Output to file
        $Line = "[$EntryType][$((Get-Date).toString('yyyy-MM-dd:hh-mm-ss'))][$env:ComputerName], $Message"
        $Line | Out-File $Path -Append
        
        switch ($EntryType)
        {
            'Verbose'     { Write-Verbose -Message $Message }
            'Information' { Write-Host $Message }
            'Warning'     { Write-Warning -Message $Message }
            'Error'       { Write-Error -ErrorRecord $ErrorRecord }
        }
    }
}
function Send-EmailNotification {
    [cmdletbinding()]
    param (
        [string]$From,
        [string]$SMTPServer,
        [string]$Subject,
        [string]$Body,
        [string[]]$EmailAddresses
    )
    
    Send-MailMessage -To $EmailAddresses -From $From -Subject $Subject -BodyAsHtml -Body $Body -SmtpServer $SMTPServer
    
}

function Decrypt-Backup {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [System.IO.FileInfo]$BackupFile,

        [parameter(Mandatory=$false,
            ParameterSetName='PasswordFile',
            Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$PasswordFile,

        [parameter(Mandatory=$false,
            ParameterSetName='Passphrase',
            Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Passphrase
    )

    begin {

        if (-not (Test-Path -Path $BackupFile)) {
            Write-Log -EntryType Error -Message "Decrypt-Backup: Backup File $BackupFile does not exist, stopping."
            break
        } else {
            # Create decrypted file name
            if ($BackupFile.Extension -eq '.gpg') {
                Write-Log -EntryType Information -Message "Decrypt-Backup: Backup file does have a .gpg extension."
                $DecryptedLocation = "/tmp/$(($BackupFile | Select-Object -expandproperty Name).Replace('.gpg',''))"
            } else {
                $DecryptedLocation = "/tmp/$($BackupFile | Select-Object -expandproperty Name)"
            }
            Write-Log -entrytype Information -Message "Decrypt-Backup: Decrypted Location: $DecryptedLocation"
        }
        # Verify the password file exists before proceeding
        if ($PSCmdlet.ParameterSetName -eq "PasswordFile") {
            if (-not (Test-Path -Path $PasswordFile)) {
                if (-not (Test-Path -Path $PasswordFile)) {
                    Write-Log -EntryType Error -Message "Decrypt-Backup: Password File $PasswordFile does not exist, stopping."
                    break
                }
            }
        }

        $Success = $false
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq "PasswordFile") {
            Write-log -EntryType Information -Message "Decrypt-Backup: Attempting to decrypt backup file $BackupFile with Password file $PasswordFile."
            gpg --batch --passphrase-file $PasswordFile --output $DecryptedLocation --decrypt $BackupFile
        } elseif ($PSCmdlet.ParameterSetName -eq "Passphrase") {
            Write-log -EntryType Information -Message "Decrypt-Backup: Attempting to decrypt backup file $BackupFile with a given passphrase."
            gpg --batch --passphrase $Passphrase --output $DecryptedLocation --decrypt $BackupFile
        }
        if (Test-Path -Path $DecryptedLocation -ErrorAction silentlyContinue) {
            Write-Log -entrytype Information -Message "Decrypt-Backup: Successfully decrypted backup $BackupFile"
            $Success = $true
        } else {
            Write-Log -EntryType Error -Message "Decrypt-Backup: Failed to decrypt backup $BackupFile."
        }
    }
    end {
        if ($Success) {
            return $DecryptedLocation
        } else {
            return $null
        }
    }
}

function Get-ExtractLocation {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [System.IO.FileInfo]$ArchiveFile
    )

    begin {
        
        $Extension = ($ArchiveFile).Extension
        Write-Log -EntryType Information -Message "Get-ExtractLocation: Archive File ($ArchiveFile) has extension $Extension."

    }

    end {
        return (($ArchiveFile | Select-Object -ExpandProperty FullName).Replace($Extension,''))
    }
}
function Extract-Backup {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [System.IO.FileInfo]$ArchiveFile
    )

    begin {
        if (-not (Test-Path -Path $ArchiveFile)) {
            Write-Log -entrytype Error -Message "Extract-Backup: Archive File $ArchiveFile doesn't exist, stopping."
            break
        }

        # Remove the extensions of the file to get a folder name
        $ExtractLocation = Get-ExtractLocation -ArchiveFile $ArchiveFile

        if (-not (Test-Path -Path $ExtractLocation)) {
            Write-Log -EntryType Information -Message "Extract-Backup: Extract Location $ExtractLocation doesn't exist, creating said location."
            if ($PSVersionTable.Platform -eq 'Unix') {
                Write-Log -EntryType Information -Message "Extract-Backup: (Linux Env) Attempting to make location $ExtractLocation."
                mkdir --parents $ExtractLocation
            } else {
                Write-Log -EntryType Information -Message "Extract-Backup: Attempting to make location $ExtractLocation."
                New-Item -Path $ExtractLocation -ItemType Directory -Force
            }
        }

        $Success = $false
    }

    process {
        Write-Log -EntryType Information -Message "Extract-Backup: Attempting to extract $ArchiveFile to extract location $ExtractLocation"
        tar --extract -f $ArchiveFile --directory $ExtractLocation

        # Verify extraction
        $ExtractedItems = Get-ChildItem -Path $ExtractLocation -Recurse
        if ($ExtractedItems.Count -gt 3) {
            Write-Log -EntryType Information -Message "Extract-Backup: Extraction was successful."
            $Success = $true
        } else {
            Write-Log -EntryType Error -Message "Extract-Backup: Doesn't appear the extraction succeeded."
        }
    }

    end {
        if ($Success) {
            return $ExtractedItems
        } else {
            return $null
        }
    }
}
function Restore-Backup {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [System.Object[]]$ExtractedItems,

        [parameter(Mandatory,
            Position=1)]
        [System.IO.FileInfo]$ArchiveFile
    )

    begin {
        $ExtractLocation = Get-ExtractLocation -ArchiveFile $ArchiveFile

        if ($null -eq $ExtractLocation -or $ExtractLocation -eq "") {
            Write-Log -EntryType Error -Message "Restore-Backup: Could not retrieve the extract location of Archive File $ArchiveFile."
            break
        }
        $Destination = $null
    }

    process {
        foreach ($Item in $ExtractedItems) {
            # if item isn't a directory, proceed
            if ($item -isnot [System.IO.DirectoryInfo]) {
                # Remove the unimportant parent directories from the destination (e.g., /tmp/BitwardenBackup-x-x-)
                $Destination = (($Item | Select-Object -ExpandProperty FullName).Replace($ExtractLocation,''))

                Write-Log -EntryType Information -Message "Restore-Backup: Attempting to restore item $item at location $Destination."

                # Attempt to replace data
                try {
                    Copy-Item -Path $($Item.Fullname) -Destination $Destination -Force -ErrorAction Stop
                } catch {
                    $Message = $_
                    Write-Log -EntryType Error -Message "Restore-Backup: Failed to copy $Item to destination $Destination because of error $Message."
                    break
                }
            }
        }
    }
}

function Stop-Bitwarden {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [string]$ScriptLocation
    )
    begin {
        if (-not (Test-Path -Path $ScriptLocation)) {
            Write-Log -EntryType Error -Message "Stop-Bitwarden: Could not stop Bitwarden because script file ($ScriptLocation) does not exist."
            break
        }

        # If Bitwarden is running, this process should exist.
        $SQLProcess = Get-Process -Name sqlservr -ErrorAction SilentlyContinue
        $Count = 0
        $Stopped = $false
    }
    
    process {
        if ($null -ne $SQLProcess -or $SQLProcess -ne "") {
            Write-Log -EntryType Information -Message "Stop-Bitwarden: Attempting to stop Bitwarden with script file $ScriptLocation."
            if ($PSVersionTable.Platform -eq 'Unix') {
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
                    Write-Log -EntryType Error -Message "Stop-Bitwarden: Failed to stop Bitwarden, stopping."
                    $Stopped = $false
                } else {
                    Write-Log -EntryType Information -Message "Stop-Bitwarden: Successfully stopped Bitwarden."
                    $Stopped = $true
                }

            } else {
                # Insert other versions here
                Write-Log -EntryType Error -Message "Stop-Bitwarden: Cannot stop Bitwarden as this function was only programmed for Unix."
                $Stopped = $false
            }
        } else {
            Write-Log -EntryType Information -Message "Stop-Bitwarden: Bitwarden is not running, no need to stop."
            $Stopped = $true
        }
    }

    end {
        return $Stopped
    }
}

function Start-Bitwarden {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [string]$ScriptLocation
    )
    begin {
        if (-not (Test-Path -Path $ScriptLocation)) {
            Write-Log -EntryType Error -Message "Start-Bitwarden: Could not start Bitwarden because script file ($ScriptLocation) does not exist."
            break
        }

        # If Bitwarden is running, this process should exist.
        $SQLProcess = Get-Process -Name sqlservr -ErrorAction SilentlyContinue
        $Count = 0
        $Started = $false
    }
    
    process {
        if ($null -eq $SQLProcess -or $SQLProcess -eq "") {
            Write-Log -EntryType Information -Message "Start-Bitwarden: Attempting to start Bitwarden with script file $ScriptLocation."
            if ($PSVersionTable.Platform -eq 'Unix') {
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
                    Write-Log -EntryType Error -Message "Start-Bitwarden: Failed to start Bitwarden, stopping."
                    $Started = $false
                } else {
                    Write-Log -EntryType Information -Message "Start-Bitwarden: Successfully started Bitwarden."
                    $Started = $true
                }

            } else {
                # Insert other versions here
                Write-Log -EntryType Error -Message "Start-Bitwarden: Cannot start Bitwarden as this function was only programmed for Unix."
                $Started = $false
            }
        } else {
            Write-Log -EntryType Information -Message "Start-Bitwarden: Bitwarden is already running, no need to start."
            $Started = $true
        }
    }

    end {
        return $Started
    }
}
#endregion

#region Script Run Area

# Check if the user is root
if ($PSVersionTable.Platform -eq "Unix") {
    if ($(whoami) -ne "root") {
        Write-Log -EntryType Error -Message "Main: You must run this script as root, stopping."
        break
    }
}

# Check if the bitwarden script exists
if (-not (Test-Path -Path $BitwardenServiceScript)) {
    Write-Log -EntryType Error -Message "Main: Bitwarden Service Script $BitwardenServiceScript does not exist, stopping."
    break
}

if ($PSCmdlet.ParameterSetName -eq "Passwordfile") {
    if (-not (Test-Path -Path $PasswordFile)) {
        Write-Log -EntryType Error -Message "Main: Password File $PasswordFile does not exist, stopping."
        break
    } else {
        Write-Log -EntryType Information -Message "Main: Password file $PasswordFile exists."
    }
}

# Verify if the provided backup file exists
if (-not (Test-Path -Path $BackupFile)) {
    Write-Log -EntryType Error -Message "Main: Backup File $BackupFile does not exist, stopping."
    break
} else {
    # Store the backup file 
    $Backup = Get-Item -Path $BackupFile
    # Make sure the file extension is a .pgp
    if (($Backup | Select-Object -expandproperty Extension) -ne '.gpg') {
        Write-Log -EntryType Error -Message "Main: The provided Backup File $Backup is not a .gpg extension. Stopping."
        break
    }

    if ($PSCmdlet.ParameterSetName -eq "PasswordFile") {
        Write-Log -EntryType Information -Message "`nMain: Attempting to decrypt backup $($Backup.FullName) with password file $PasswordFile."
        $DecryptedBackupLocation = Decrypt-Backup -BackupFile $($Backup.FullName) -PasswordFile $PasswordFile
    } elseif ($PSCmdlet.ParameterSetName -eq "Passphrase") {
        Write-Log -EntryType Information -Message "`nMain: Attempting to decrypt backup $($Backup.FullName) with a given passphrase."
        $DecryptedBackupLocation = Decrypt-Backup -BackupFile $($Backup.FullName) -Passphrase $Passphrase
    }

    # Failed to decrypt backup
    if ($null -eq $DecryptedBackupLocation -or $DecryptedBackupLocation -eq "") {
        Write-Log -EntryType Error -Message "Main: Failed to decrypt backup $($Backup.FullName), stopping."
        break
    } else {
        Write-Log -EntryType Information -Message "Main: Successfully decrypted backup $($Backup.FullName), which resides at $DecryptedBackupLocation."
    }

    # Unzip Archive
    try {
        Write-Log -EntryType Information -Message "`nMain: Attempting to extract $DecryptedBackupLocation"
        $DecryptedBackup = Get-Item -Path $DecryptedBackupLocation -ErrorAction Stop

        # If the extension is a .tar, unzip it.
        if ($DecryptedBackup.Extension -eq '.tar') {
            $DecryptedBackupItems = Extract-Backup -ArchiveFile $DecryptedBackup
            
            if ($null -eq $DecryptedBackupItems -or $DecryptedBackupItems -eq "") {
                Write-Log -EntryType Error -Message "Main: Failed to extract archive file $DecryptedBackup, stopping/deleting decrypted file."
                try {
                    Remove-Item -Path $($DecryptedBackup.Fullname) -ErrorAction Stop
                } catch {
                    Write-Log -EntryType Error -Message "Main: Failed to delete decrypted backup $($DecryptedBackup.FullName)."
                    break
                }
                break    
            }
        } else {
            Write-Log -EntryType Error -Message "Main: The decrypted backup has an extension of $($DecryptedBackup.Extension), which isn't .tar, stopping."
            break
        }
    } catch {
        $Message = $_
        Write-Log -EntryType Error -Message "Main: Failed to store the decrypted backup ($DecryptedBackupLocation) because of error $Message"
        break
    }
    
    # Check if run.sh exists or we cannot stop BitWarden
    if (-not (Test-Path -Path $script:BITWARDEN_RUN_FILE)) {
        Write-Log -EntryType Warning -Message "Main: Missing $script:BITWARDEN_RUN_FILE, attempt to copy from backup."
        if (Test-path -Path "$DecryptedBackupLocation//opt/bitwarden/bwdata/scripts/run.sh") {
            Copy-Item -Path "$DecryptedBackupLocation//opt/bitwarden/bwdata/scripts/run.sh" -Destination $script:BITWARDEN_RUN_FILE -Force
        }
    }

    # Attempting to stop Bitwarden before restoring backup
    $Stopped = Stop-Bitwarden -ScriptLocation $BitwardenServiceScript

    # Proceed with restoration if Bitwarden has stopped
    if ($Stopped -eq $true) {
        # Move Backup Files to their appropriate location
        Write-Log -EntryType Information -Message "`nMain: Attempting to restore backup files."
        Restore-Backup -ExtractedItems $DecryptedBackupItems -ArchiveFile $DecryptedBackup
    } else {
        Write-Log -EntryType Error -Message "Main: Bitwarden wasn't stopped, which makes restoration impossible."
    }

    # Start Bitwarden after the restore
    if ($Stopped -eq $true) {
        Write-Log -EntryType Information -Message "`nMain: Attempting to start Bitwarden."
        $Started = Start-Bitwarden -ScriptLocation $BitwardenServiceScript

        if ($Started -eq $true) {
            Write-Log -EntryType Information -Message "Main: Bitwarden has successfully started."
        } else {
            Write-Log -EntryType Error -Message "Main: Bitwarden failed to start."
        }
    }
    # Delete extracted backup and unencrypted backup
    try {
        $ExtractLocation = Get-ExtractLocation -ArchiveFile $DecryptedBackup
        Write-Log -EntryType Information -Message "`nMain: Attempting to remove extracted backup $ExtractLocation"
        Remove-Item -Path $ExtractLocation -Recurse -Force -ErrorAction Stop

        if (-not (Test-Path -Path $ExtractLocation)) {
            Write-Log -EntryType Information -Message "Main: Successfully removed extracted backup $ExtractLocation."
        } else {
            Write-Log -EntryType Warning -Message "Main: Failed to remove extracted backup $ExtractLocation."
        }

    } catch {
        $Message = $_
        Write-Log -EntryType Error -Message "Main: Failed to delete extracted backup $ExtractLocation due to error $Message."
        break
    }

    # Delete the decrypted archive
    try {
        Write-Log -EntryType Information -Message "`nMain: Attempting to remove decrypted backup $($DecryptedBackup.FullName)."
        Remove-Item -path $($DecryptedBackup.FullName) -Force -ErrorAction Stop

        if (-not (Test-Path -Path $($DecryptedBackup.FullName))) {
            Write-Log -EntryType Information -Message "Main: Successfully removed decrypted backup $($DecryptedBackup.FullName)."
        } else {
            Write-Log -EntryType Warning -Message "Main: Failed to remove decrypted backup $($DecryptedBackup.FullName)."
        }
    } catch {
        $Message = $_
        Write-Log -EntryType Error -Message "Main: Failed to delete decrypted backup $($DecryptedBackup.FullName) due to error $Message."
        break
    }
}
#endregion
