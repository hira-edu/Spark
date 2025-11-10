[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$RulePrefix = "Spark Remote Desktop"
)

$pattern = "^" + [Regex]::Escape($RulePrefix) + "\b"
$rules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match $pattern }

if (-not $rules) {
    Write-Verbose "No Spark firewall rules found with prefix '$RulePrefix'."
    return
}

foreach ($rule in $rules) {
    if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove-NetFirewallRule')) {
        $rule | Remove-NetFirewallRule
    }
}
