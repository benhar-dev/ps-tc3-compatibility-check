# -------------------------------------------------------------------------------------------------------------------------------
# Copyright 2022 benhar-dev
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
# files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, 
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software 
# is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# -------------------------------------------------------------------------------------------------------------------------------

# This software is a work in progress

cls

function ConsoleLog-Title {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $Info
	)
	Write-Host $Info
    Write-Host ("-" * $Info.Length)
}

function ConsoleLog-Pass {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $Info
	)
    Write-Host -NoNewline '['
	Write-Host -ForegroundColor Green -NoNewLine ([Char]8730)
    Write-Host -NoNewline '] '
	Write-Host $Info
}

function ConsoleLog-Fail {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $Info
	)
    Write-Host -NoNewline '['
	Write-Host -ForegroundColor Red -NoNewLine 'X'
    Write-Host -NoNewline '] '
	Write-Host $Info
}

Function pause ($message)
{
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# ----------------------------------------------------------------------------

ConsoleLog-Title "TwinCAT Runtime Compatibility Check (Beta)"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 
    ConsoleLog-Pass "Script running as Administrator"
}else {
    ConsoleLog-Fail "Script not running as Administrator. Please run this by right clicking and select 'Run as Administrator'"
}

# services
# --------

$hypervheartbeat = Get-Service -name vmicheartbeat

if ($hypervheartbeat.Status -contains 'Stopped') { 
    ConsoleLog-Pass "Hyper-V Heartbeat service is stopped."
}else {
    ConsoleLog-Fail "Hyper-V Heartbeat service is running.  This indicates that Hyper-V is enabled."
}


# bcd check
# ---------

$bcd = bcdedit

if ($bcd.Contains('disabledynamictick      Yes')) { 
  ConsoleLog-Pass "Disable dynamic tick has been correctly set."
}else {
  ConsoleLog-Fail "Disable dynamic tick has not been set. Please run C:\TwinCAT\3.1\System\win8settick.bat as Administrator"
}

if ($bcd.Contains('useplatformtick         Yes')) { 
  ConsoleLog-Pass "Use platform tick has been correctly set."
}else {
  ConsoleLog-Fail "Use platform tick has not been set. Please run C:\TwinCAT\3.1\System\win8settick.bat as Administrator"
}


# Windows feature check
# ---------------------

#Get-WindowsOptionalFeature -Online -FeatureName *Hyper-V*


# done 
pause('Done')