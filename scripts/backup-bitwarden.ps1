<#
.Synopsis
    This script performs a backup operation on our on-premise bitwarden server.

.DESCRIPTION
    This script requires autofs to be setup on said local server and moves backups to said autofs location (preferably a fileserver). The script will keep backups after x provided days.

.PARAMETER PasswordFile
    The password file that holds the passphrase that will be used to encrypt backups.

.PARAMETER FinalBackupLocation
    The destination of the encrypted backup (e.g., '/backups')

.PARAMETER Incremental
    This switch will backup if there's been any changes to the Bitwarden database within the past hour. 

.PARAMETER All
    This switch will perform a full backup of BitWarden.

.PARAMETER Days
    Pass amount of days to keep backups. For example, if you set this to '10', the script will delete all backups greater than 10 days from current date. You must also
    give the correct backup location that houses said existing backups.

.PARAMETER BackupName
    If you wish to overwrite the default backup name, use this parameter to do so. You must end the filename with a .tar file extension (e.g., backup.tar)

.PARAMETER EmailAddresses
    The email address(es) in which notifications will be sent out to.

.PARAMETER SMTPServer
    The SMTP Server the script will use to send emails from.

.PARAMETER From
    The Email Address that will be sending said emails.

.PARAMETER LogFile
    The location where the log file will reside.

.EXAMPLE
    ./Backup-Bitwarden.ps1 -PasswordFile '/opt/bitwarden/password_file' -FinalBackupLocation '/backups' -All
    
    Perform a full BitWarden Backup with the default retention days of 31 and store the backups at location /backups

.EXAMPLE
    ./Backup-Bitwarden.ps1 -PasswordFile './password_file' -FinalBackupLocation '/backups' -All -EmailAddresses 'zack@zackshomelab.com'
    
    Perform a full BitWarden Backup with a retention of 5 days (this will remove backups older than 5 days) and store the backup at /backups'

.EXAMPLE
    ./Backup-Bitwarden.ps1 -PasswordFile '/opt/bitwarden/password_file' -FinalBackupLocation '/backups' -Incremental -days 10 -LogFile '/root/bitwarden_backup.log'
    
    Perform an incremental Bitwarden Backup with the provided password file and cleanup backups to only allow 10 days worth of backups to be stored at the final destination. Also, 
    set the script's log file to be stored at /root/bitwarden_backup.log'
#>
[cmdletbinding()]
param (
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='IncrementPasswordFile')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='AllPasswordFile')]
        [ValidateScript({Test-Path -Path $_})]
    [string]$PasswordFile,

    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='IncrementPasswordPhrase')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='AllPasswordPhrase')]
        [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$PasswordPhrase,

    [parameter(Mandatory,
        Position=1)]
        [ValidateScript({Test-Path -Path $_})]
    [string]$FinalBackupLocation,

    [parameter(Mandatory,
        Position=2,
        ParameterSetName='IncrementPasswordFile')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='IncrementPasswordPhrase')]
    [switch]$Incremental,

    [parameter(Mandatory,
        Position=2,
        ParameterSetName='AllPasswordFile')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='AllPasswordPhrase')]
    [switch]$All,

    [parameter(Mandatory=$false,
        helpMessage="How many days should we retain backups?",
        Position=3)]
        [ValidateRange(1, 365)]
    [int]$Days = 31,

    [parameter(Mandatory=$false,
        Position=4)]
        [ValidateScript({$_ -match '^.*\.tar$'})]
    [string]$BackupName,

    [Parameter(Mandatory=$false,
        Position=5)]
    [string]$LogFile = './backup-bitwarden.log'

    [Parameter(Mandatory=$false,
        Position=6)]
    [string[]]$EmailAddresses,

    [Parameter(Mandatory=$false,
        Position=7,
        helpMessage="What's your SMTP Server's address? (e.g., contoso-com.mail.protection.outlook.com)")]
    [string]$SMTPServer,

    [Parameter(Mandatory=$false,
        Position=8,
        HelpMessage="What's the email address that'll send the email?")]
    [string]$From,
)

BEGIN {
    #region VARIABLES
    $script:LOG_FILE = $LogFile

    $FINAL_BACKUP_LOCATION = $FinalBackupLocation

    # The incremental directories to be backed up
    $INCREMENTAL_DIRECTORIES = "/opt/bitwarden/bwdata/env", "/opt/bitwarden/bwdata/core/attachments", "/opt/bitwarden/bwdata/mssql/data"

    # The entire backup of Bitwarden
    $ALL_DIRECTORIES = "/opt/bitwarden/bwdata"

    # Path of the Vault log (this is used to determine if we need to make an incremental backup)
    $VAULT_LOG = "/opt/bitwarden/bwdata/mssql/data/vault_log.ldf"

    # Generate a backup name if one wasn't provided
    if (-not $PSBoundParameters.ContainsKey('BackupName')) {
        $BackupName = New-ZHLBWBackupName
    }

    # The file path of the Encrypted Backup
    $ENCRYPTED_BACKUP_NAME = "$FINAL_BACKUP_LOCATION/$BackupName"

    # Add the items or directories to be removed by the script if we encounter an error or end said script
    $CLEANUP_ITEMS = @($BackupName)

    # Send Emails if this is true
    if ($PSBoundParameters.ContainsKey('EmailAddresses') -and $PSBoundParameters.ContainsKey('From') -and $PSBoundParameters.ContainsKey('SMTPServer')) {
        $CAN_SEND_EMAIL = $true
    } else {
        $CAN_SEND_EMAIL = $false
    }
    
    #endregion



    #region FUNCTIONS
    function Write-Log {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory, Position=0)]
            [ValidateNotNullOrEmpty()]
            [String]$Message,

            [Parameter(Mandatory=$false, Position=1)]
            [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
            [String]$EntryType = "Information",

            [parameter(Mandatory=$false, Position=2)]
            [ValidateNotNullOrEmpty()]
            [string]$Path = $script:LOG_FILE,
        )
        
        begin {
            
            # Check if the log level an error or an error record was submitted
            if ($EntryType -eq 'Error') {
                $ErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $Message, 'Unknown', 'NotSpecified', $null
            }
        }
        
        process {
            # Output to file
            $Line = "[$EntryType][$((Get-Date).toString('yyyy-MM-dd:hh-mm-ss'))][$env:ComputerName], $Message"
            $Line | Out-File $Path -Append
            
            switch ($EntryType) {
                'Verbose'     { Write-Verbose -Message $Message }
                'Information' { Write-Output $Message }
                'Warning'     { Write-Warning -Message $Message }
                'Error'       { Write-Error -ErrorRecord $ErrorRecord }
            }
        }
    }

    #region Exit Codes
    $exitcode_NoChangesInPastHour = 0
    $exitcode_MissingZHLBitWardenModule = 10
    $exitcode_FailCreatingBackup = 11
    $exitcode_FailEncryptingBackup = 12
    $exitcode_FailMovingEncryptBackup = 13
    $exitcode_FailFindingBackupAfterMove = 14
    $exitcode_FailRemoveOldBackups = 15
    #endregion
}

PROCESS {

    #region Prereqs

    # Verify if we can import the ZHLBitWarden Module:
    if (-not (Get-Module -Name ZHLBitWarden -ErrorAction SilentlyContinue)) {
        try {
            Import-Module -Name ZHLBitWarden -ErrorAction Stop
        } catch {
            Write-Log -EntryType Warning -Message "Main: Error importing PowerShell Module ZHLBitWarden."
            Write-Log -EntryType Warning -Message "Main: Verify the module exists in '/usr/local/share/powershell/Modules'"
            exit $exitcode_MissingZHLBitWardenModule
        }
    }
    #endregion


    #region Create Backup
    try {
        if ($PSCmdlet.ParameterSetName -like 'Increment*') {
            # Check if Bitwarden's Vault Log has had any changes within the past hour
            # If this is true, create incremental backup.
            if (-not (Get-Item -Path $VAULT_LOG | Where-Object {$_.LastWriteTime -ge ((Get-Date).AddHours(-1))})) {
                Write-Log "Main: Vault hasn't changed within the past hour, no need for an incremental backup. Stopping script."
                exit $exitcode_NoChangesInPastHour
            }

            Write-Log "Main: Vault has changed within the hour, creating incremental Backup..."
            Backup-ZHLBWBitWarden -Items $INCREMENTAL_DIRECTORIES -BackupName $BackupName -ErrorAction Stop
        } elseif ($PSCmdlet.ParameterSetName -like 'All*') {
            # Create a full backup
            Write-Log "`nMain: Creating full Backup..."
            Backup-ZHLBWBitWarden -Items $ALL_DIRECTORIES -BackupName $BackupName -ErrorAction Stop
        }
        
    } catch {
        Write-Log -EntryType Warning "Main: Failed creating a BiTwarden Backup due to $_"
        exit $exitcode_FailCreatingBackup
    }
    
    Write-Log "Main: Successfully created backup $BackupName!"
    #endregion



    #region Encrypt Backup
    try {
        Write-Log "`nMain: Attempting to encrypt Backup $BackupName."
        if ($PSCmdlet.ParameterSetName -like '*PasswordFile*') {
            Lock-ZHLBWBackup -BackupFileLocation $BackupName -PasswordFileLocation $PasswordFile -ErrorAction Stop
        } elseif ($PSCmdlet.ParameterSetName -like '*PasswordPhrase*') {
            Lock-ZHLBWBackup -BackupFileLocation $BackupName -PasswordPhrase $PasswordPhrase -ErrorAction Stop
        }
        
    } catch {
        $Message = $_
        Write-Log -EntryType Warning -Message "Main: Failed to encrypt backup $BackupName because of error $Message"
        if ($CAN_SEND_EMAIL) {
            Send-ZHLBWEmail -EmailAddresses $EmailAddresses -From $From -SmtpServer $SMTPServer -Subject "FAILURE: BitWarden Backup" -Body "Encryption was successful but failed to delete unencrypted backup because of error: $Message" -ErrorAction SilentlyContinue
        }
        Remove-ZHLBWItems -Items $CLEANUP_ITEMS
        exit $exitcode_FailEncryptingBackup
    }

    # Encryption was successful, delete unencrypted backup
    Write-Log "`nMain: Encryption was successful, removing unencrypted backup."
    Remove-Item -Path $BackupName -Force
    #endregion


    #region Move Encrypted Backup to Final Destination
    try {
        Write-Log "`nMain: Moving Encrypted Backup to final backup destination: $FINAL_BACKUP_LOCATION."
        Move-Item -Path $ENCRYPTED_BACKUP_NAME -Destination $FINAL_BACKUP_LOCATION -ErrorAction Stop
    } catch {
        $Message = $_
        Write-Log -EntryType Warning -Message "Main: Failed to move encrypted backup $ENCRYPTED_BACKUP_NAME due to error $Message"
        if ($CAN_SEND_EMAIL) {
            Send-ZHLBWEmail -EmailAddresses $EmailAddresses -From $From -SMTPServer $SMTPServer -Subject "FAILURE: BitWarden Backup" -Body "Failed to move encrypted backup $ENCRYPTED_BACKUP_NAME because of error $Messag" -ErrorAction SilentlyContinue
        }
        exit $exitcode_FailMovingEncryptBackup
    }

    # Verify the backup is at its final location
    if (-not Test-Path -Path $ENCRYPTED_BACKUP_NAME) {
        Write-Log -EntryType Warning -Message "Main: Could not find created backup $ENCRYPTED_BACKUP_NAME."
        if ($CAN_SEND_EMAIL) {
            Send-ZHLBWEmail -EmailAddresses $EmailAddresses -From $From -SmtpServer $SMTPServer -Subject "FAILURE: BitWarden Backup" -Body "Successfully created backup but could not find it after moving to $ENCRYPTED_BACKUP_NAME"
        }
        exit $exitcode_FailFindingBackupAfterMove
    }

    Write-Log "`nMain: Successfully created backup $ENCRYPTED_BACKUP_NAME. Sending success email (if Send-ZHLBWEmail was configured)."
    if ($CAN_SEND_EMAIL) {
        Send-ZHLBWEmail -EmailAddresses $EmailAddresses -From $From -SmtpServer $SMTPServer -Subject "SUCCESS: BitWarden Backup" -Body "Successfully created backup $ENCRYPTED_BACKUP_NAME."
    }
    #endregion



    #region Delete old backups
    try {
        # Delete Backups older than $Days at backup location $FINAL_BACKUP_LOCATION
        Write-Log "`nMain: Check if there's any backups that are more than $Days days old."
        Remove-ZHLBWBackups -Days $Days -BackupLocation $FINAL_BACKUP_LOCATION -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed to remove old backups due to error $_"
        exit $exitcode_FailRemoveOldBackups
    }
    #endregion
}