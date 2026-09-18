<#
.SYNOPSIS
  Read-only inventory of AI tooling, automation, and access on a Windows machine.

.DESCRIPTION
  Collects what runs on its own, what AI tooling is installed, what holds
  credentials, and what can reach the network. Writes findings.json (raw) and
  report.md (human readable) to an output folder.

  READ ONLY. Nothing is installed, changed, or deleted. Secret VALUES are never
  written to disk, only names and short prefixes.

  Run it with the machine owner present and with their permission.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Invoke-SteelClawAIAudit.ps1
  powershell -ExecutionPolicy Bypass -File .\Invoke-SteelClawAIAudit.ps1 -Since '2026-01-01' -Until '2026-01-15'
#>

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $env:USERPROFILE ("Desktop\ai-audit-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [datetime]$Since = (Get-Date).AddDays(-120),
    [datetime]$Until = (Get-Date),
    [int]$MaxDepth = 4,
    [int]$MaxEvents = 300
)

$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$findings = [ordered]@{}
$flags    = New-Object System.Collections.Generic.List[string]

# Values matching these never leave the machine in the report.
$secretPatterns = @(
    'sk-ant-[A-Za-z0-9_\-]{10,}',
    'sk-[A-Za-z0-9]{20,}',
    'ghp_[A-Za-z0-9]{20,}',
    'AKIA[0-9A-Z]{16}',
    'xox[baprs]-[A-Za-z0-9\-]{10,}',
    'ey[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
)

function Protect-Secrets {
    param([string]$Text)
    if (-not $Text) { return $Text }
    foreach ($p in $secretPatterns) { $Text = [regex]::Replace($Text, $p, '[REDACTED]') }
    return $Text
}

function Add-Section {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ("  collecting: {0}" -f $Name)
    try   { $findings[$Name] = @(& $Body) }
    catch {
        if ($_.Exception.Message -match 'No events were found') { $findings[$Name] = @() }
        else { $findings[$Name] = @{ error = $_.Exception.Message } }
    }
}

# Counts only real records, never an error placeholder, so flags can't fire on a failed section.
function Measure-Real {
    param($Section, [string]$RequiredProperty)
    if (-not $Section) { return 0 }
    @($Section | Where-Object { $_ -isnot [hashtable] -and $_.PSObject.Properties.Name -contains $RequiredProperty }).Count
}

Write-Host "AI stack audit, read only. Output: $OutDir"

# ---------------------------------------------------------------- what runs on its own
Add-Section 'ScheduledTasks' {
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo
        [pscustomobject]@{
            TaskName  = $_.TaskName
            TaskPath  = $_.TaskPath
            State     = "$($_.State)"
            Action    = (Protect-Secrets (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '))
            LastRun   = $info.LastRunTime
            LastResult= $info.LastTaskResult
            NextRun   = $info.NextRunTime
        }
    }
}

Add-Section 'StartupItems' {
    Get-CimInstance Win32_StartupCommand |
        Select-Object Name, @{n='Command';e={ Protect-Secrets $_.Command }}, Location, User
}

Add-Section 'NonWindowsServices' {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -notlike '*\Windows\*' } |
        Select-Object Name, DisplayName, State, StartMode, @{n='PathName';e={ Protect-Secrets $_.PathName }}
}

# ---------------------------------------------------------------- AI and dev tooling
Add-Section 'Binaries' {
    foreach ($exe in 'claude','openclaw','ant','node','npm','npx','python','python3','git','docker','wsl','uv','bun') {
        $cmd = Get-Command $exe -ErrorAction SilentlyContinue
        if ($cmd) {
            # Microsoft Store app-execution aliases are 0-byte reparse points. Running one opens the Store.
            $isStub = $false
            try { $isStub = ($cmd.Source -like '*\WindowsApps\*') -and ((Get-Item $cmd.Source -Force).Length -eq 0) } catch {}
            $ver = ''
            if (-not $isStub -and $exe -ne 'wsl') { $ver = (& $exe --version 2>$null | Select-Object -First 1) }
            $stubNote = ''
            if ($isStub) { $stubNote = 'Not actually installed. This is a Store placeholder, not a working binary.' }
            [pscustomobject]@{
                Name        = $exe
                Source      = $cmd.Source
                Version     = "$ver"
                StoreStub   = $isStub
                Note        = $stubNote
            }
        }
    }
}

Add-Section 'GlobalNpmPackages' {
    if (Get-Command npm -ErrorAction SilentlyContinue) { (npm ls -g --depth=0 2>$null) -join "`n" } else { 'npm not installed' }
}

Add-Section 'WslDistros' {
    # Only query if a distro is actually registered. Calling wsl.exe blind triggers a 60 second
    # interactive install prompt, which must never happen on someone else's machine.
    if (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss') {
        (Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            "$($p.DistributionName)  base: $($p.BasePath)"
        }) -join "`n"
    } else { 'No WSL distributions registered' }
}

Add-Section 'DockerContainers' {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        (docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' 2>$null) -join "`n"
    } else { 'docker not installed' }
}

Add-Section 'ConfigDirectories' {
    foreach ($d in '.claude','.openclaw','.anthropic','.config','.aws','.ssh') {
        $p = Join-Path $env:USERPROFILE $d
        if (Test-Path $p) {
            [pscustomobject]@{
                Path      = $p
                Modified  = (Get-Item $p).LastWriteTime
                FileCount = (Get-ChildItem $p -Recurse -File -Force -Depth 3 | Measure-Object).Count
            }
        }
    }
}

# ---------------------------------------------------------------- credentials, names only
Add-Section 'CredentialEnvVars' {
    $names = @()
    foreach ($scope in 'Process','User','Machine') {
        ([Environment]::GetEnvironmentVariables($scope)).GetEnumerator() |
            Where-Object { $_.Key -match 'ANTHROPIC|CLAUDE|OPENAI|OPENROUTER|API|TOKEN|SECRET|KEY' } |
            ForEach-Object {
                $v = [string]$_.Value
                $names += [pscustomobject]@{
                    Scope  = $scope
                    Name   = $_.Key
                    Length = $v.Length
                    Prefix = if ($v.Length -gt 8) { $v.Substring(0,8) + '...' } else { 'short-or-empty' }
                }
            }
    }
    $names
}

Add-Section 'DotEnvFiles' {
    Get-ChildItem $env:USERPROFILE -Recurse -Force -Filter '.env*' -Depth $MaxDepth |
        Select-Object FullName, LastWriteTime, Length
}

# ---------------------------------------------------------------- what he did
Add-Section 'ShellHistoryFileInfo' {
    $paths = @((Get-PSReadLineOption).HistorySavePath,
               "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") |
             Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Select-Object -Unique
    foreach ($h in $paths) {
        if (Test-Path $h) {
            $f = Get-Item $h
            [pscustomobject]@{
                Path      = $f.FullName
                Modified  = $f.LastWriteTime
                Created   = $f.CreationTime
                Lines     = (Get-Content $h | Measure-Object -Line).Lines
                Note      = 'PSReadLine history has NO per-line timestamps. Date filtering is not possible here. Use the event log sections for timestamped activity.'
            }
        }
    }
}

Add-Section 'ShellHistoryAll' {
    $h = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $h) { Get-Content $h -Tail 500 | ForEach-Object { Protect-Secrets $_ } }
}

Add-Section 'ShellHistoryOfInterest' {
    $h = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $h) {
        Get-Content $h | ForEach-Object { Protect-Secrets $_ } |
            Where-Object { $_ -match 'claude|openclaw|ant |anthropic|npm|pip|python|node|git |curl|iwr|irm|Invoke-WebRequest|schtasks|ScheduledTask|New-Service|docker|wsl|setx|\[Environment\]|Set-ExecutionPolicy|\.ps1|key|token|secret' } |
            Select-Object -Last 300
    }
}

Add-Section 'InstalledSoftware' {
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object DisplayName |
        Select-Object DisplayName, Publisher, DisplayVersion, InstallDate |
        Sort-Object InstallDate -Descending
}

Add-Section 'RemoteAccessTools' {
    $watch = 'AnyDesk','TeamViewer','RustDesk','ngrok','Tailscale','ZeroTier','Chrome Remote','Splashtop','VNC','Parsec'
    $hits = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                             'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object { $n = $_.DisplayName; $n -and ($watch | Where-Object { $n -like "*$_*" }) } |
        Select-Object DisplayName, Publisher, InstallDate
    if ($hits) { $flags.Add("Remote access software present: " + (($hits.DisplayName) -join ', ')) }
    $hits
}

Add-Section 'LocalUsers' { Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description }

Add-Section 'FilesWrittenInWindow' {
    # Excludes zero-byte Store aliases, virtualization icon caches, and browser caches,
    # which otherwise bury the handful of files a human actually created.
    $noise = '\\WindowsApps\\', '\\Parallels\\Shared Applications\\', '\\VMware\\', '\\INetCache\\',
             '\\Code Cache\\', '\\Cache\\', '\\CrashDumps\\', '\\Temp\\.*\.tmp$'
    Get-ChildItem $env:USERPROFILE -Recurse -File -Force -Depth $MaxDepth |
        Where-Object {
            $f = $_
            $f.LastWriteTime -ge $Since -and $f.LastWriteTime -le $Until -and $f.Length -gt 0 -and
            -not (@($noise | Where-Object { $f.FullName -match $_ }).Count)
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 200 FullName, LastWriteTime, Length
}

Add-Section 'InstalledSoftwareInWindow' {
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object { $_.DisplayName -and $_.InstallDate -match '^\d{8}$' } |
        ForEach-Object {
            $d = [datetime]::ParseExact($_.InstallDate,'yyyyMMdd',$null)
            if ($d -ge $Since.Date -and $d -le $Until.Date) {
                [pscustomobject]@{ DisplayName = $_.DisplayName; Publisher = $_.Publisher; Installed = $d.ToString('yyyy-MM-dd') }
            }
        } | Sort-Object Installed -Descending
}

# ---------------------------------------------------------------- timestamped activity in the window
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$findings['RunContext'] = [pscustomobject]@{ Elevated = $isAdmin; Note = 'Security log and some System log entries require an elevated shell. Everything else runs fine as the normal user.' }

Add-Section 'TaskSchedulerEvents' {
    Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=$Since; EndTime=$Until; Id=@(106,140,141) } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, Id,
            @{n='Meaning';e={ switch ($_.Id) { 106 {'task registered'} 140 {'task updated'} 141 {'task deleted'} default {"id $($_.Id)"} } }},
            @{n='Detail';e={ Protect-Secrets (($_.Message -split "`r?`n") -join ' ') }}
}

Add-Section 'PowerShellScriptBlockEvents' {
    Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$Since; EndTime=$Until; Id=4104 } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, @{n='Script';e={ Protect-Secrets (($_.Message -split "`r?`n" | Select-Object -First 4) -join ' ') }}
}

Add-Section 'ServiceInstallEvents' {
    Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$Since; EndTime=$Until; Id=7045 } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, @{n='Detail';e={ Protect-Secrets (($_.Message -split "`r?`n") -join ' ') }}
}

Add-Section 'MsiInstallEvents' {
    Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$Since; EndTime=$Until; Id=@(11707,1033) } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, @{n='Detail';e={ (($_.Message -split "`r?`n") | Select-Object -First 1) }}
}

Add-Section 'AccountAndRemoteLogonEvents' {
    if (-not $isAdmin) { return 'Skipped. Re-run in an elevated shell to read the Security log.' }
    $acct = Get-WinEvent -FilterHashtable @{ LogName='Security'; StartTime=$Since; EndTime=$Until; Id=@(4720,4732,4738) } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, Id, @{n='Detail';e={ (($_.Message -split "`r?`n") | Select-Object -First 2) -join ' ' }}
    $rdp = Get-WinEvent -FilterHashtable @{ LogName='Security'; StartTime=$Since; EndTime=$Until; Id=4624 } -MaxEvents 2000 |
        Where-Object { $_.Message -match 'Logon Type:\s+10' } |
        Select-Object TimeCreated, @{n='Detail';e={ 'remote interactive logon' }}
    @($acct) + @($rdp)
}

# ---------------------------------------------------------------- network posture
Add-Section 'NonSystemProcesses' {
    Get-Process | Where-Object { $_.Path -and $_.Path -notlike "$env:SystemRoot*" } |
        Select-Object Name, Id, Path, StartTime | Sort-Object StartTime -Descending
}

Add-Section 'ListeningPorts' {
    Get-NetTCPConnection -State Listen | ForEach-Object {
        [pscustomobject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            Process      = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
        }
    } | Sort-Object LocalPort -Unique
}

# ---------------------------------------------------------------- flags
$agentBins = @($findings['Binaries'] | Where-Object { $_.Name -in @('claude','openclaw','ant') })
if ($agentBins.Count) {
    $flags.Add("Agent tooling installed locally: " + ($agentBins.Name -join ', '))
}
$credCount = Measure-Real $findings['CredentialEnvVars'] 'Name'
if ($credCount) {
    $flags.Add("$credCount credential-shaped environment variables set. Anything at User or Machine scope survives reboot and may route billing to an API key.")
}
$regEvents = @($findings['TaskSchedulerEvents'] | Where-Object { $_.Id -eq 106 })
if ($regEvents.Count) { $flags.Add("$($regEvents.Count) scheduled tasks were REGISTERED inside the examined window. See TaskSchedulerEvents for exact timestamps.") }
$svcCount = Measure-Real $findings['ServiceInstallEvents'] 'TimeCreated'
if ($svcCount) { $flags.Add("$svcCount new services installed inside the window.") }
$ranTasks = @($findings['ScheduledTasks'] | Where-Object { $_.NextRun })
if ($ranTasks) { $flags.Add("$($ranTasks.Count) non-Microsoft scheduled tasks have a next run time. These only fire while the machine is awake.") }

# ---------------------------------------------------------------- triage: detected or not
function Get-SectionText { param([string]$Name) ,($findings[$Name] | Out-String) }

$hay = [ordered]@{
    tasks    = Get-SectionText 'ScheduledTasks'
    startup  = Get-SectionText 'StartupItems'
    services = Get-SectionText 'NonWindowsServices'
    bins     = Get-SectionText 'Binaries'
    npmg     = Get-SectionText 'GlobalNpmPackages'
    cfg      = Get-SectionText 'ConfigDirectories'
    hist     = (Get-SectionText 'ShellHistoryAll') + (Get-SectionText 'ShellHistoryOfInterest')
    sb       = Get-SectionText 'PowerShellScriptBlockEvents'
    sw       = Get-SectionText 'InstalledSoftware'
    proc     = Get-SectionText 'NonSystemProcesses'
    files    = Get-SectionText 'FilesWrittenInWindow'
    wsl      = Get-SectionText 'WslDistros'
    docker   = Get-SectionText 'DockerContainers'
}
$everything = ($hay.Values -join "`n")

$checks = New-Object System.Collections.Generic.List[object]
function Add-Check {
    param([string]$Category, [string]$Name, [bool]$Found, [string]$Detail = '')
    $r = 'not detected'
    if ($Found) { $r = 'FOUND' }
    $checks.Add([pscustomobject]@{ Category = $Category; Check = $Name; Result = $r; Detail = $Detail })
}

# Tool signatures. Each is a regex searched across binaries, packages, config dirs,
# installed software, processes, history, and script block events.
$tools = [ordered]@{
    'Claude Code'                = 'claude\.exe|@anthropic-ai/claude-code|\\\.claude\b|claude-code'
    'OpenClaw'                   = 'openclaw'
    'Claude Managed Agents CLI'  = '\bant\.exe\b|anthropics/tap|managed-agents'
    'Hermes agent framework'     = 'hermes[-_ ]?(agent|framework|ai)|nousresearch'
    'LangChain or LangGraph'     = 'langchain|langgraph|langsmith'
    'CrewAI'                     = 'crewai|crew_ai'
    'AutoGen'                    = 'autogen'
    'n8n'                        = '\bn8n\b'
    'Flowise'                    = 'flowise'
    'Ollama (local models)'      = 'ollama'
    'LM Studio (local models)'   = 'lm ?studio'
    'OpenAI tooling'             = 'openai|chatgpt'
    'Zapier or Make'             = 'zapier|make\.com|integromat'
    'Node.js runtime'            = 'node\.exe|nodejs|npm ls'
    'Python (real, not a stub)'  = 'python\.exe(?!.*WindowsApps)|Python 3'
}
foreach ($t in $tools.GetEnumerator()) {
    $hit = [regex]::IsMatch($everything, $t.Value, 'IgnoreCase')
    $where = @()
    foreach ($k in $hay.Keys) { if ([regex]::IsMatch($hay[$k], $t.Value, 'IgnoreCase')) { $where += $k } }
    Add-Check 'AI tooling' $t.Key $hit ($where -join ', ')
}

# Automation: the Windows equivalent of cron, and anything set to launch itself.
$aiPattern = 'claude|openclaw|anthropic|openai|\bant\.exe|langchain|crewai|n8n|agent|\.py\b|node\.exe|curl|Invoke-WebRequest'
$aiTasks = @($findings['ScheduledTasks'] | Where-Object { $_.Action -and $_.Action -match $aiPattern })
Add-Check 'Automation' 'Scheduled tasks referencing AI tooling' ($aiTasks.Count -gt 0) (($aiTasks.TaskName) -join ', ')

$anyTasks = @($findings['ScheduledTasks'] | Where-Object { $_.TaskName })
Add-Check 'Automation' 'Any non-Microsoft scheduled tasks at all' ($anyTasks.Count -gt 0) "$($anyTasks.Count) task(s)"

$regInWindow = @($findings['TaskSchedulerEvents'] | Where-Object { $_.Id -eq 106 })
Add-Check 'Automation' 'Tasks registered inside the examined window' ($regInWindow.Count -gt 0) "$($regInWindow.Count) registration event(s)"

$aiStartup = @($findings['StartupItems'] | Where-Object { $_.Command -and $_.Command -match $aiPattern })
Add-Check 'Automation' 'Startup items referencing AI tooling' ($aiStartup.Count -gt 0) (($aiStartup.Name) -join ', ')

$aiSvc = @($findings['NonWindowsServices'] | Where-Object { $_.PathName -and $_.PathName -match $aiPattern })
Add-Check 'Automation' 'Services referencing AI tooling' ($aiSvc.Count -gt 0) (($aiSvc.Name) -join ', ')

$svcNew = Measure-Real $findings['ServiceInstallEvents'] 'TimeCreated'
Add-Check 'Automation' 'Services installed inside the window' ($svcNew -gt 0) "$svcNew event(s)"

$localListeners = @($findings['ListeningPorts'] | Where-Object {
    $_.LocalAddress -eq '127.0.0.1' -and $_.Process -and
    $_.Process -notmatch 'svchost|System|lsass|wininit|services|spoolsv|prl_|vmware'
})
Add-Check 'Automation' 'Local gateway style listener (possible agent daemon)' ($localListeners.Count -gt 0) (($localListeners | ForEach-Object { "$($_.Process):$($_.LocalPort)" }) -join ', ')

# Credentials and billing exposure
$credVars = @($findings['CredentialEnvVars'] | Where-Object { $_.Name })
$apiVars  = @($credVars | Where-Object { $_.Name -match 'ANTHROPIC|OPENAI|OPENROUTER' })
Add-Check 'Credentials' 'AI provider API key in environment (billing risk)' ($apiVars.Count -gt 0) (($apiVars | ForEach-Object { "$($_.Name) [$($_.Scope)]" }) -join ', ')
Add-Check 'Credentials' 'Any credential shaped environment variables' ($credVars.Count -gt 0) "$($credVars.Count) variable(s)"

$envFiles = @($findings['DotEnvFiles'] | Where-Object { $_.FullName })
Add-Check 'Credentials' '.env files in the user profile' ($envFiles.Count -gt 0) "$($envFiles.Count) file(s)"

$cfgDirs = @($findings['ConfigDirectories'] | Where-Object { $_.Path })
Add-Check 'Credentials' 'Agent config directories (.claude, .openclaw, .aws)' ($cfgDirs.Count -gt 0) (($cfgDirs.Path) -join ', ')

# Access and risk
$rat = @($findings['RemoteAccessTools'] | Where-Object { $_.DisplayName })
Add-Check 'Access' 'Remote access software installed' ($rat.Count -gt 0) (($rat.DisplayName) -join ', ')

$extraUsers = @($findings['LocalUsers'] | Where-Object { $_.Enabled -and $_.Name -notmatch 'Administrator|DefaultAccount|Guest|WDAGUtility' -and $_.Name -ne $env:USERNAME })
Add-Check 'Access' 'Extra enabled local accounts' ($extraUsers.Count -gt 0) (($extraUsers.Name) -join ', ')

$wslFound = ($hay['wsl'] -notmatch 'No WSL distributions registered')
Add-Check 'Access' 'WSL distributions registered (agents can hide here)' $wslFound ''

# Verdict
$localAutomation = ($aiTasks.Count + $aiStartup.Count + $aiSvc.Count + $localListeners.Count) -gt 0
$verdict = if ($localAutomation) {
    'LOCAL AUTOMATION PRESENT. Something on this machine is configured to run AI tooling on its own. It only runs while the machine is powered on and logged in.'
} else {
    'NO LOCAL AI AUTOMATION DETECTED. Nothing on this machine is set up to run AI tooling by itself.'
}

$triage = New-Object System.Text.StringBuilder
[void]$triage.AppendLine("# AI audit triage")
[void]$triage.AppendLine("")
[void]$triage.AppendLine("Machine: $env:COMPUTERNAME   User: $env:USERNAME   Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm')   Elevated: $isAdmin")
[void]$triage.AppendLine("Window examined: $($Since.ToString('yyyy-MM-dd')) to $($Until.ToString('yyyy-MM-dd'))")
[void]$triage.AppendLine("")
[void]$triage.AppendLine("## Verdict")
[void]$triage.AppendLine($verdict)
[void]$triage.AppendLine("")
[void]$triage.AppendLine("Cloud-side automation (Cowork scheduled tasks, Claude Code routines, Managed Agents) is INVISIBLE from this machine. To test: power the machine off overnight and check whether anything still ran.")
if (-not $isAdmin) { [void]$triage.AppendLine("")
    [void]$triage.AppendLine("Not elevated, so the Security log was skipped. New accounts and remote logons were not checked.") }
[void]$triage.AppendLine("")
[void]$triage.AppendLine("## Hits")
$hits = @($checks | Where-Object Result -eq 'FOUND')
if ($hits.Count -eq 0) { [void]$triage.AppendLine("Nothing of interest detected.") }
else { foreach ($c in $hits) { [void]$triage.AppendLine("- [$($c.Category)] $($c.Check): $($c.Detail)") } }
[void]$triage.AppendLine("")
foreach ($cat in ($checks.Category | Select-Object -Unique)) {
    [void]$triage.AppendLine("## $cat")
    foreach ($c in ($checks | Where-Object Category -eq $cat)) {
        $mark = '[ ]'
        if ($c.Result -eq 'FOUND') { $mark = '[X]' }
        $line = "$mark $($c.Check)"
        if ($c.Detail) { $line += "  ($($c.Detail))" }
        [void]$triage.AppendLine($line)
    }
    [void]$triage.AppendLine("")
}
[void]$triage.AppendLine("## Check in the browser, with the owner")
[void]$triage.AppendLine("- platform.claude.com: API keys, last used date, spend per key")
[void]$triage.AppendLine("- claude.ai settings: plan tier, seats, who else is in the workspace")
[void]$triage.AppendLine("- myaccount.google.com/connections: apps with Gmail and Drive access, read or write")
[void]$triage.AppendLine("- card statement: flat plan charge versus usage charges that move month to month")
[void]$triage.AppendLine("")
[void]$triage.AppendLine("Full evidence: report.md (readable) and findings.json (raw).")
$triage.ToString() | Out-File (Join-Path $OutDir 'triage.md') -Encoding utf8

# ---------------------------------------------------------------- write output
$findings | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir 'findings.json') -Encoding utf8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# AI stack audit")
[void]$md.AppendLine("")
[void]$md.AppendLine("Machine: $env:COMPUTERNAME   User: $env:USERNAME   Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
[void]$md.AppendLine("Window examined for file writes: $($Since.ToString('yyyy-MM-dd')) to $($Until.ToString('yyyy-MM-dd'))")
[void]$md.AppendLine("")
[void]$md.AppendLine("## Flags")
if ($flags.Count -eq 0) { [void]$md.AppendLine("None raised automatically.") }
else { foreach ($f in $flags) { [void]$md.AppendLine("- $f") } }
[void]$md.AppendLine("")
foreach ($k in $findings.Keys) {
    $v = $findings[$k]
    $count = if ($v -is [array]) { $v.Count } else { 1 }
    [void]$md.AppendLine("## $k ($count)")
    [void]$md.AppendLine('```')
    [void]$md.AppendLine((($v | Format-List | Out-String).Trim()))
    [void]$md.AppendLine('```')
    [void]$md.AppendLine("")
}
[void]$md.AppendLine("## Not visible from this machine, check in the browser with the owner")
[void]$md.AppendLine("- platform.claude.com: API keys, last used, spend per key")
[void]$md.AppendLine("- claude.ai settings: plan tier, seats, who else is in the workspace")
[void]$md.AppendLine("- myaccount.google.com/connections: apps with Gmail and Drive access, read or write")
[void]$md.AppendLine("- card statement: flat plan charges versus usage charges that move month to month")
[void]$md.AppendLine("- overnight test: close the laptop, check LastRun times in the morning")
$md.ToString() | Out-File (Join-Path $OutDir 'report.md') -Encoding utf8

Write-Host ""
Write-Host "Done. Files written:"
Write-Host "  $(Join-Path $OutDir 'triage.md')      <- read this one"
Write-Host "  $(Join-Path $OutDir 'report.md')"
Write-Host "  $(Join-Path $OutDir 'findings.json')"
Write-Host ""
Write-Host $verdict
if ($hits.Count) {
    Write-Host ""
    Write-Host "Hits:"
    $hits | ForEach-Object { Write-Host "  [$($_.Category)] $($_.Check)  $($_.Detail)" }
}
if ($flags.Count) { Write-Host ""; $flags | ForEach-Object { Write-Host "  FLAG: $_" } }
