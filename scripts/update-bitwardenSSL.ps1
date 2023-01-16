<#
.Synopsis
    This script will renew BitWarden's Let's Encrypt certificate.

.DESCRIPTION
    This script will renew BitWarden's Let's Encrypt certificate.

.PARAMETER ConfigFile
    The path of the docker configuration file for BitWarden (default is: '/opt/bitwarden/bwdata/config.yml')

.PARAMETER URL
    The URL of your BitWarden instance. If one isn't provided, the script will retrieve it from ConfigFile.

.PARAMETER BitWardenScript
    The path of BitWarden's service script (default is: '/opt/bitwarden/bitwarden.sh').

.PARAMETER ServiceAccount
    The name of your service account for the BitWarden service (default is: bitwarden).

.PARAMETER SendEmail
    Toggle this switch if you would like the script to send an email based off of your settings in the Global Environments file.

.PARAMETER EmailAddresses
    Input the email addresses that should receive the email from this script.

.PARAMETER LogFile
    The path of the log file to store the output of this script (default is: './Update-BitWardenSSL.log').

.EXAMPLE
    ./update-bitwardenSSL.ps1

    The above will utilize the default values to renew BitWarden's SSL certificate with Let's Encrypt.

.EXAMPLE
    ./update-bitwardenSSL.ps1 -SendEmail -EmailAddresses 'zack@zackshomelab.com'

    The above will send a notification if a SSL Renewal occurred.
    
.NOTES
    Author - Zack
.LINK
    GitHub (Scripts) - https://github.com/ZacksHomeLab/BitWarden-Scripts
    GitHub (Documentation) - https://github.com/ZacksHomeLab/BitWarden
#>
[cmdletbinding()]
param (
    [parameter(Mandatory=$false,
        Position=0)]
    [ValidateScript({(Test-Path -Path $_) -and ($_ -match "^(.*)\.yml$")})]
    [string]$ConfigFile = '/opt/bitwarden/bwdata/config.yml',

    [parameter(Mandatory=$false,
        Position=1,
        HelpMessage="What is the URL of your BitWarden website? (e.g., bitwarden.zackshomelab.com)")]
        [ValidateScript({$_ -Match "[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"})]
    [string]$URL,

    [Parameter(Mandatory=$false,
        Position=3,
        ValueFromPipelineByPropertyName,
        helpMessage="What's the name and path of the Bitwarden service script? (Must end in .sh)")]
        [ValidateScript({Test-Path -Path $_ -and $_ -match "^(.*)\.sh$"})]
    [string]$BitWardenScript = '/opt/bitwarden/bitwarden.sh',

    [parameter(Mandatory=$false,
        Position=4,
        helpMessage="What is the username of the service account for your server (e.g., bitwarden)?")]
        [ValidateNotNullOrEmpty()]
    [string]$ServiceAccount = 'bitwarden',

    [parameter(Mandatory,
        Position=5,
        ParameterSetName='SendEmail')]
    [switch]$SendEmail,

    [parameter(Mandatory,
        Position=6,
        ParameterSetName='SendEmail',
        helpMessage="What Email Addresses should receive the update report? (Must also add '-SendEmail' switch to enable this)")]
    [string[]]$EmailAddresses,

    [Parameter(Mandatory=$false, 
        Position=7)]
    [string]$LogFile = "./Update-BitWardenSSL.log"
)

begin {
    #region Variables
    $script:LOG_FILE = $LogFile

    # Retrieve the URL ourselves (if one wasn't provided)
    if (-not $PSBoundParameters.containskey('URL')) {
        $URL = (Select-String -Path $ConfigFile -Pattern "URL:").tostring().split('http://')[-1]
    } else {
        # Incase someone gives http or https in their URL, remove it.
        if ($URL -match '^(http|https)://(.*)$') {
            $URL = ($URL).split('://')[-1]
        }
        
        # If someone gave a trailing '/' at the end of their URL, remove it.
        if ($URL[-1] -eq '/') {
            $URL = $URL.split('/')[0]
        }
    }

    $SERVICE_ACCOUNT = $ServiceAccount

    # Location of the cert files generated by certbot
    $LE_PRIVATE_KEY = "/etc/letsencrypt/live/$URL/privkey.pem"
    $LE_FULLCHAIN = "/etc/letsencrypt/live/$URL/fullchain.pem"
    $LE_CA_FILE = "/etc/letsencrypt/live/$URL/chain.pem"

    # Location to store the certificates in BitWarden's environment
    $BITWARDEN_SSL_PRIVATE_KEY = "/opt/bitwarden/bwdata/ssl/$URL/privkey.pem"
    $BITWARDEN_SSL_FULLCHAIN = "/opt/bitwarden/bwdata/ssl/$URL/fullchain.pem"
    $BITWARDEN_SSL_CA_FILE = "/opt/bitwarden/bwdata/ssl/$URL/chain.pem"

    # This array will be used to validate if the below files actually exist. If they don't, the script will NOT run.
    $ITEMS_TO_VERIFY = @($LE_PRIVATE_KEY, $LE_FULLCHAIN, $LE_CA_FILE, $BITWARDEN_SSL_PRIVATE_KEY, $BITWARDEN_SSL_FULLCHAIN, $BITWARDEN_SSL_CA_FILE)
    $ITEMS_MISSING = @()

    # We will use this splatter to send an email if '-sendEmail' was given
    $EMAIL_PARAMS = @{}

    # Email settings will be stored in this hash table
    $EMAIL_SETTINGS = @{}

    # Reset these variables
    $SUCCESS = $null
    $CERTBOT = $null
    $CHOWN = $null
    $item = $null
    $FROM = $null
    $SMTP_PORT = $null
    $SMTP_SERVER = $null
    $Creds = $null
    $UseSSL = $null
    $PASS = $null
    #endregion



    #region Exit Codse
    $exitcode_DidNotRenew = 1
    $exitcode_FoundSSLFiles = 2

    $exitcode_NotRoot = 10
    $exitcode_MissingFiles = 11
    $exitcode_MissingCertbot = 12
    $exitcode_MissingChown = 13
    $exitcode_FailRunningCertbot = 14
    $exitcode_MissingZHLBitWardenModule = 15
    $exitcode_MissingSSLFiles = 16
    $exitcode_FailReplacePrivateKey = 17
    $exitcode_FailReplaceFullChain = 18
    $exitcode_FailReplaceCA = 19
    $exitcode_FailUpdatingOwnership = 20
    $exitcode_FailRestartingBitWarden = 21
    $exitcode_MissingGlobalEnv = 22
    $exitcode_FailSendingEmail = 23
    $exitcode_FailGatheringEmailSettings = 24
    #endregion

    #region Functions
    function Write-Log {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory, Position=0)]
            [ValidateNotNullOrEmpty()]
            [String]$Message,

            [Parameter(Mandatory=$false, Position=1)]
            [ValidateSet('Verbose', 'Info', 'Warning', 'Error')]
            [String]$EntryType = "Info",

            [parameter(Mandatory=$false, Position=2)]
            [ValidateNotNullOrEmpty()]
            [string]$Path = $script:LOG_FILE
        )
        
        begin {
            
            # Check if the log level an error or an error record was submitted
            if ($EntryType -eq 'Error') {
                $ErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $Message, 'Unknown', 'NotSpecified', $null
            }
        }
        
        process {
            # Output to file
            $Line = "[$EntryType][$((Get-Date).toString('yyyy-MM-dd:hh-mm-ss'))], $Message"
            $Line | Out-File $Path -Append
            
            switch ($EntryType) {
                'Verbose'     { Write-Verbose -Message $Message }
                'Info'        { Write-Output $Message }
                'Warning'     { Write-Warning -Message $Message }
                'Error'       { Write-Error -ErrorRecord $ErrorRecord }
            }
        }
    }
    #endregion
    
    #region Pre-Reqs
    # Check if the user is root
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -ne "root") {
            Write-Log -EntryType Warning -Message "Main: You must run this script as root, stopping."
            exit $exitcode_NotRoot
        }
    }

    # Verify if we can import the ZHLBitWarden Module:
    if (-not (Get-Module -Name ZHLBitWarden -ErrorAction SilentlyContinue)) {
        try {
            if (Test-Path -Path "$($Home)/.local/share/powershell/Modules/ZHLBitWarden.psm1") {
                Import-Module -Name "$($Home)/.local/share/powershell/Modules/ZHLBitWarden.psm1"
            } elseif (Test-Path -Path "/usr/local/share/powershell/Modules/ZHLBitWarden.psm1") {
                Import-Module -Name "/usr/local/share/powershell/Modules/ZHLBitWarden.psm1" -ErrorAction Stop
            }
            
        } catch {
            Write-Log -EntryType Warning -Message "Main: Error importing PowerShell Module ZHLBitWarden."
            Write-Log -EntryType Warning -Message "Main: Verify the module exists in '$($Home)/.local/share/powershell/Modules/ OR /usr/local/share/powershell/Modules/'"
            exit $exitcode_MissingZHLBitWardenModule
        }
    }
    # Verify certbot is installed
    if (-not (Get-Command -Name 'certbot' -ErrorAction SilentlyContinue)) {
        Write-Log -EntryType Warning -Message "Main: Missing the certbot command, is it installed?"
        exit $exitcode_MissingCertbot
    } else {
        # Store the path of CertBot into this variable
        $CERTBOT = (Get-Command -Name 'certbot' | Select-Object -first 1).Source
    }

    # Verify chown exists
    if (-not (Get-Command -Name 'chown' -ErrorAction SilentlyContinue)) {
        Write-Log -EntryType Warning -Message "Main: Missing the chown command. This is required to update SSL Certificate ownership."
        exit $exitcode_MissingChown
    } else {
        # Store the path of CertBot into this variable
        $CHOWN = (Get-Command -Name 'chown' | Select-Object -first 1).Source
    }

    # Verify we have all the required SSL files
    Write-Log "Main: Verify if we have all the required files to run this script."
    $SUCCESS = Test-ZHLBWSSLFiles -Data $ITEMS_TO_VERIFY

    if (-not $SUCCESS) {
        Write-Log -EntryType Warning -Message "Main: You do not have the required files to utilize this script, stopping."
        exit $exitcode_MissingSSLFiles
    } else {
        Write-Log "Main: All the SSL files have been validated. Proceed with renewal."
    }
    #endregion
}

process {

    #region Renew SSL Certificate
    try {
        Write-Log "`nMain: Renewing SSL certificate with Certbot..."
        Start-Process -FilePath $CERTBOT -ArgumentList "renew" -Wait -RedirectStandardError $script:LOG_FILE -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed running certbot with error $_"
        exit $exitcode_FailRunningCertbot
    }
    #endregion


    #region Verify if SSL Certificate renewed
    Write-Log "`nMain: Certbot finished running, validating if our SSL certificated renewed for $URL..."
    # This would return true if our SSL certificate did NOT renew
    if (-not (Get-Item -Path $LE_PRIVATE_KEY | Where-Object LastWriteTime -ge ((Get-Date).AddDays(-1)))) {
        Write-Log "Main: SSL Certificate for $URL is not due for renewal. Stopping."
        exit $exitcode_DidNotRenew
    }

    Write-Log "Main: SSL Certificate has renewed. BitWarden's Files must be updated."
    #endregion

    #region Replace BitWarden's files
    Write-Log "`nMain: Replacing $BITWARDEN_SSL_PRIVATE_KEY with $LE_PRIVATE_KEY"
    # '-L follows symbolic links
    yes | cp -Lf $LE_PRIVATE_KEY $BITWARDEN_SSL_PRIVATE_KEY
    if ($LastExitCode -ne 0) {
        Write-Log -EntryType Warning -Message "Main: Failed replacing $BITWARDEN_SSL_PRIVATE_KEY with $LE_PRIVATE_KEY."
        exit $exitcode_FailReplacePrivateKey
    }

    Write-Log "Main: Replacing $BITWARDEN_SSL_FULLCHAIN with $LE_FULLCHAIN"
    # '-L follows symbolic links
    yes | cp -Lf $LE_FULLCHAIN $BITWARDEN_SSL_FULLCHAIN
    if ($LastExitCode -ne 0) {
        Write-Log -EntryType Warning -Message "Main: Failed replacing $BITWARDEN_SSL_FULLCHAIN with $LE_FULLCHAIN."
        exit $exitcode_FailReplaceFullChain
    }

    Write-Log "Main: Replacing $BITWARDEN_SSL_CA_FILE with $LE_CA_FILE"
    # '-L follows symbolic links
    yes | cp -Lf $LE_CA_FILE $BITWARDEN_SSL_CA_FILE
    if ($LastExitCode -ne 0) {
        Write-Log -EntryType Warning -Message "Main: Failed replacing $BITWARDEN_SSL_CA_FILE with $LE_CA_FILE."
        exit $exitcode_FailReplaceCA
    }
    #endregion

    #region Change ownership of BitWarden's SSL files
    try {
        Write-Log "`nMain: Changing ownership of BitWarden's SSL files to service account $SERVICE_ACCOUNT."
        Start-Process -FilePath $CHOWN -ArgumentList "$SERVICE_ACCOUNT $BITWARDEN_SSL_PRIVATE_KEY $BITWARDEN_SSL_FULLCHAIN $BITWARDEN_SSL_CA_FILE" -Wait `
            -RedirectStandardError $script:LOG_FILE -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed changing ownership of BitWarden's SSL files. Due to error $_"
        exit $exitcode_FailUpdatingOwnership
    }
    
    #endregion


    #region Restart BitWarden
    try {
        Write-Log "`nMain: Restart BitWarden for the new SSL certificates."
        Restart-ZHLBWBitWarden -ScriptLocation $BitWardenScript -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed restarting BitWarden due to error $_"
        exit $exitcode_FailRestartingBitWarden
    }

    #endregion


    #region Send Email
    if ($PSCmdlet.ParameterSetName -eq 'SendEmail') {
        # The location of the global environment variables. Verify it exists.
        $GLOBAL_ENV = '/opt/bitwarden/bwdata/env/global.override.env'
        if (-not (Test-Path -Path $GLOBAL_ENV)) {
            Write-Log -EntryType Warning -Message "Main: Global Environment file $GLOBAL_ENV does not exist. Could not retrieve SMTP settings."
            exit $exitcode_MissingGlobalEnv
        }
        try {
            Write-Log "Main: Gathering Email Settings from global environment file $GLOBAL_ENV"
            $EMAIL_SETTINGS = Get-ZHLBWEmailSettings -GlobalEnv $GLOBAL_ENV -ErrorAction Stop
        } catch {
            Write-Log -EntryType Warning -Message "Main: Failed gathering Email Settings from $GLOBAL_ENV due to error $_"
            exit $exitcode_FailGatheringEmailSettings
        }
        
        # Create the parameter splat
        $EMAIL_PARAMS.add('EmailAddresses', $EmailAddresses)
        $EMAIL_PARAMS.add('FROM', $EMAIL_SETTINGS['From'])
        $EMAIL_PARAMS.add('SMTPServer', $EMAIL_SETTINGS['SMTPServer'])
        $EMAIL_PARAMS.add('SMTPPort', $EMAIL_SETTINGS['SMTPPort'])
        $EMAIL_PARAMS.add('Subject', "BitWarden: SSL Certificate Renewed!")
        $EMAIL_PARAMS.add('Body', "The Let's Encrypt certificate has renewed.")
        $EMAIL_PARAMS.add('UseSSL', $EMAIL_SETTINGS['UseSSL'])

        # If a password was given, create the credentials variable
        if ($null -ne $PASS) {
            $EMAIL_PARAMS.add('Creds', $EMAIL_SETTINGS['Creds'])
        }
        $EMAIL_PARAMS.add('ErrorAction', 'Stop')

        try {
            Send-ZHLBWEmail @EMAIL_PARAMS
        } catch {
            Write-Log -EntryType Warning -Message "Main: Failed sending email due to Error $_"
            exit $exitcode_FailSendingEmail
        }
    }
    #endregion
}