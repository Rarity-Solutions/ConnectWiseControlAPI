# Define server variables
$username = $env:CONNECTWISE_ADMIN_USER
$password = $env:CONNECTWISE_ADMIN_PASSWORD
$otpSecret = $env:CONNECTWISE_ADMIN_OTP_SECRET
$server = $env:CONNECTWISE_SERVER_URL

# Validate server variables
if (-not $username -or -not $password -or -not $otpSecret -or -not $server) {
    Write-Host "Error: One or more required environment variables are not set." -ForegroundColor Red
    Write-Host "Ensure the following environment variables are set:" -ForegroundColor Yellow
    Write-Host "CONNECTWISE_ADMIN_USER, CONNECTWISE_ADMIN_PASSWORD, CONNECTWISE_ADMIN_OTP_SECRET, CONNECTWISE_SERVER_URL" -ForegroundColor Yellow
    exit
}

# Set SSL/TLS protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Install API Module
$documentsPath=[Environment]::GetFolderPath('MyDocuments');$url='https://github.com/Rarity-Solutions/ConnectWiseControlAPI/archive/refs/heads/main.zip';$moduleName='ConnectWiseControlAPI';$modulePath=Join-Path $documentsPath 'WindowsPowerShell\Modules';$tempPath=Join-Path $env:TEMP ($moduleName+'.zip');Invoke-WebRequest -Uri $url -OutFile $tempPath;$tempDir='.'+$moduleName+'_temp';$extractPath=Join-Path $HOME $tempDir;Expand-Archive -Path $tempPath -DestinationPath $extractPath -Force;$sourceFolder=Join-Path $extractPath ('ConnectWiseControlAPI-main/'+$moduleName);$destinationFolder=Join-Path $modulePath $moduleName;if (!(Test-Path $destinationFolder)) {New-Item -Path $destinationFolder -ItemType Directory | Out-Null};Copy-Item -Path "$sourceFolder\*" -Destination $destinationFolder -Recurse -Force; Remove-Item $tempPath, $extractPath -Recurse -Force

# Import the ConnectWise Control API module
Import-Module $moduleName -Force

# Connect to the ConnectWise Control API
$ConnectSplat = @{
    Server = $server
    Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, (ConvertTo-SecureString -String $password -AsPlainText -Force)
    Secret = ConvertTo-SecureString -String $otpSecret -AsPlainText -Force
}

try {
    Connect-CWC @ConnectSplat
    Write-Host "Successfully connected to ScreenConnect API." -ForegroundColor Green
} catch {
    Write-Host "Failed to connect to ScreenConnect API. Please check your credentials and server information." -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
    exit
}

# Create a new user and assign access
function New-SCUserAndAssign {
    try {
        $newUserDisplayName = Read-Host "Enter the new user display name"
        $newUserNameEmail = Read-Host "Enter the user's email address"
        $newUserPassword = Read-Host "Enter the user's password"
        $newUserRole = 'Remote Workforce'

        $newUserSecurePassword = ConvertTo-SecureString -String $newUserPassword -AsPlainText -Force
        $newUserCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $newUserNameEmail, $newUserSecurePassword

        $newUserParams = @{
            Credentials = $newUserCredentials
            Email = $newUserNameEmail
            DisplayName = $newUserDisplayName
            OTP = 'email'
            SecurityGroups = $newUserRole
        }
        New-CWCUser @newUserParams
        Write-Host "User '$newUserNameEmail' created successfully." -ForegroundColor Green

        $computerInfo = Select-SCComputer
        if ($computerInfo.Success) {
            New-CWCRemoteWorkforceAssignment -SessionID $computerInfo.Session.SessionID -UserName $newUserNameEmail -DisplayName $newUserDisplayName
            Write-Host "Access assigned to '$($computerInfo.Session.Name)' for user '$newUserNameEmail'." -ForegroundColor Green
        }
    } catch {
        Write-Host "An error occurred while creating the user and assigning access." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Enhanced Select-SCComputer function
function Select-SCComputer {
    try {
        # Get the computer sessions
        $sessions = Get-CWCSession -Type 'Access' | Sort-Object Name
        if ($sessions.Count -eq 0) {
            throw "No computers found in ScreenConnect"
        }

        # Display available computers
        Write-Host "`nAvailable Computers:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $sessions.Count; $i++) {
            Write-Host "$($i + 1). $($sessions[$i].Name)"
        }

        # Select a computer
        do {
            $selection = Read-Host "`nSelect computer number (1-$($sessions.Count))"
            $validSelection = $selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $sessions.Count
            if (-not $validSelection) {
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            }
        } while (-not $validSelection)

        $selectedSession = $sessions[$selection - 1]
        return @{ Success = $true; Session = $selectedSession }
    } catch {
        Write-Host "`nError occurred while selecting a computer:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return @{ Success = $false }
    }
}

# Helper function to select a user
function Select-SCUser {
    try {
        $Security = Get-CWCSecurityConfigurationInfo
        $InternalUsers = $Security.UserSources | Where-Object { $_.Users.Count -gt 0 } | Select-Object -First 1

        if (-not $InternalUsers -or $InternalUsers.Users.Count -eq 0) {
            throw "No users found in ScreenConnect"
        }

        Write-Host "`nExisting Users:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $InternalUsers.Users.Count; $i++) {
            Write-Host "$($i + 1). $($InternalUsers.Users[$i].Email) ($($InternalUsers.Users[$i].Name))"
        }

        do {
            $selection = Read-Host "`nSelect user number (1-$($InternalUsers.Users.Count))"
            $validSelection = $selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $InternalUsers.Users.Count
            if (-not $validSelection) {
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            }
        } while (-not $validSelection)

        $selectedUser = $InternalUsers.Users[$selection - 1]
        return @{ Success = $true; User = $selectedUser }
    } catch {
        Write-Host "`nError occurred while selecting a user:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return @{ Success = $false }
    }
}

function Grant-SCAccess {
    try {
        Write-Host "Granting Access to an Existing User..." -ForegroundColor Cyan
        $userInfo = Select-SCUser
        if ($userInfo.Success) {
            $computerInfo = Select-SCComputer
            if ($computerInfo.Success) {
                New-CWCRemoteWorkforceAssignment -SessionID $computerInfo.Session.SessionID -UserName $userInfo.User.Email -DisplayName $userInfo.User.Name
                Write-Host "Access granted successfully to user '$($userInfo.User.Email)' for computer '$($computerInfo.Session.Name)'." -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "An error occurred while granting access." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Delete a user account
function Delete-SCUser {
    $userInfo = Select-SCUser
    if ($userInfo.Success) {
        Remove-CWCUser -User $userInfo.User.Email
        Write-Host "User deleted successfully!" -ForegroundColor Green
    }
}

function Get-NotesForEmail {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Email
    )

    # Get all sessions
    $sessions = Get-CWCSession -Type 'Access' | Sort-Object Name

    if ($sessions.Count -eq 0) {
        Write-Host "No computers found in ScreenConnect" -ForegroundColor Red
        return
    }

    # Array to store matching notes
    $matchingNotes = @()

    Write-Host "`nSearching for notes with email: $Email..." -ForegroundColor Cyan

    # Iterate through each session and its notes
    foreach ($session in $sessions) {
        if ($session.AddedNoteEvents) {
            foreach ($note in $session.AddedNoteEvents) {
                # Check if the note contains the email
                if ($note.Data -match $Email) {
                    $matchingNotes += @{
                        SessionName = $session.Name
                        EventID     = $note.EventID
                        Note        = $note.Data
                    }
                }
            }
        }
    }

    # Display the results
    if ($matchingNotes.Count -gt 0) {
        Write-Host "`nMatching Notes Found:" -ForegroundColor Green
        $matchingNotes | ForEach-Object {
            Write-Host "Session: $($_.SessionName)" -ForegroundColor Yellow
            Write-Host "EventID: $($_.EventID)" -ForegroundColor White
            Write-Host "Note: $($_.Note)" -ForegroundColor White
            Write-Host "-----------------------------------" -ForegroundColor Cyan
        }
    } else {
        Write-Host "No notes found for email: $Email" -ForegroundColor Red
    }
}

# Retrieve Notes for a Specific Computer
function Get-NotesForComputer {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    # Get all sessions
    $sessions = Get-CWCSession -Type 'Access' | Sort-Object Name

    if ($sessions.Count -eq 0) {
        Write-Host "No computers found in ScreenConnect" -ForegroundColor Red
        return
    }

    # Filter the session by computer name
    $session = $sessions | Where-Object { $_.Name -eq $ComputerName }
    if (-not $session) {
        Write-Host "No session found for computer: $ComputerName" -ForegroundColor Red
        return
    }

    # Array to store matching notes
    $matchingNotes = @()

    Write-Host "`nSearching for notes with computer: $ComputerName..." -ForegroundColor Cyan

    # Check if the session has notes
    if ($session.AddedNoteEvents) {
        foreach ($note in $session.AddedNoteEvents) {
            $matchingNotes += @{
                SessionName = $session.Name
                EventID     = $note.EventID
                Note        = $note.Data
            }
        }
    }

    # Display the results
    if ($matchingNotes.Count -gt 0) {
        Write-Host "`nMatching Notes Found:" -ForegroundColor Green
        $matchingNotes | ForEach-Object {
            Write-Host "Session: $($_.SessionName)" -ForegroundColor Yellow
            Write-Host "EventID: $($_.EventID)" -ForegroundColor White
            Write-Host "Note: $($_.Note)" -ForegroundColor White
            Write-Host "-----------------------------------" -ForegroundColor Cyan
        }
    } else {
        Write-Host "No notes found for computer: $ComputerName" -ForegroundColor Red
    }
}

# Updated Option 4 using Select-SCComputer
function Explore-ComputerNotes {
    try {
        # Use Select-SCComputer for consistency
        $computerInfo = Select-SCComputer
        if ($computerInfo.Success) {
            # Retrieve and display notes for the selected computer
            Get-NotesForComputer -ComputerName $computerInfo.Session.Name
        }
    } catch {
        Write-Host "An error occurred while exploring computer notes." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Main Menu
do {
    Write-Host "`nScreenConnect Access Management" -ForegroundColor Cyan
    Write-Host "1. Create New User and Assign Access"
    Write-Host "2. Grant Access to Existing User"
    Write-Host "3. Delete User Account"
    Write-Host "4. Retrieve Notes for Specific Email"
    Write-Host "5. Retrieve Notes for Specific Computer"
    Write-Host "6. Exit"
    $choice = Read-Host "Select an action (1-6)"

    switch ($choice) {
        '1' { New-SCUserAndAssign }
        '2' { Grant-SCAccess }
        '3' { Delete-SCUser }
        '4' {
            try {
                Write-Host "`nRetrieve Notes for Specific Email" -ForegroundColor Cyan
                Write-Host "1. Select from existing users" -ForegroundColor Yellow
                Write-Host "2. Enter email manually" -ForegroundColor Yellow
                $subChoice = Read-Host "Select an option (1-2)"
        
                switch ($subChoice) {
                    '1' {
                        $userInfo = Select-SCUser  # Use Select-SCUser to fetch the email list
                        if ($userInfo.Success) {
                            Get-NotesForEmail -Email $userInfo.User.Email
                        }
                    }
                    '2' {
                        $manualEmail = Read-Host "Enter the email address to search for"
                        if ($manualEmail) {
                            Get-NotesForEmail -Email $manualEmail
                        } else {
                            Write-Host "No email address provided. Returning to main menu." -ForegroundColor Red
                        }
                    }
                    default {
                        Write-Host "Invalid choice. Returning to main menu." -ForegroundColor Red
                    }
                }
            } catch {
                Write-Host "An error occurred while retrieving notes for the email." -ForegroundColor Red
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        '5' { Explore-ComputerNotes }
        '6' { break }
        default { Write-Host "Invalid choice. Please try again." -ForegroundColor Red }
    }
} while ($true)