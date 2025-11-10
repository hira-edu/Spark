[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$SparkServerHost,

    [Parameter()]
    [int[]]$Ports = @(443, 6060),

    [Parameter()]
    [string]$RulePrefix = "Spark Remote Desktop",

    [Parameter()]
    [string]$ProgramPath = "C:\ProgramData\Spark\Spark.exe",

    [switch]$Force
)

function Ensure-Rule {
    param(
        [string]$DisplayName,
        [int]$Port
    )

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Write-Verbose "Skipping existing rule '$DisplayName'. Use -Force to recreate."
        return
    }
    if ($existing -and $Force) {
        Write-Verbose "Removing existing rule '$DisplayName'."
        $existing | Remove-NetFirewallRule
    }
    $params = @{
        DisplayName      = $DisplayName
        Direction        = 'Outbound'
        Action           = 'Allow'
        Enabled          = 'True'
        Profile          = 'Any'
        RemotePort       = $Port
        Protocol         = 'TCP'
        RemoteFqdn       = $SparkServerHost
        Description      = "Spark agent outbound control plane access"
    }
    if ($ProgramPath) {
        $params.Program = $ProgramPath
    }
    if ($PSCmdlet.ShouldProcess($SparkServerHost, "New-NetFirewallRule $DisplayName")) {
        New-NetFirewallRule @params | Out-Null
        Write-Verbose "Created rule '$DisplayName'."
    }
}

if (-not $Ports -or $Ports.Count -eq 0) {
    throw "At least one port must be provided."
}

foreach ($port in $Ports) {
    if (-not $port -or $port -le 0) {
        continue
    }
    $name = "$RulePrefix Outbound TCP $port"
    Ensure-Rule -DisplayName $name -Port $port
}
