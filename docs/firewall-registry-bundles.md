# Spark Firewall & Registry Policy Bundles

This guide ships ready-to-import artifacts for customers that need auditable firewall and registry baselines before rolling out the Spark remote desktop agent. Pair these bundles with `docs/network-matrix.md` and `docs/registry-footprint.md` when answering security questionnaires or staging GPO/Intune deployments.

## Bundle Inventory

| Path | Purpose |
| --- | --- |
| `scripts/policies/firewall/SparkFirewall-AllowOutbound.ps1` | Creates outbound-only Windows Defender Firewall rules scoped to your Spark control plane host/ports. |
| `scripts/policies/firewall/SparkFirewall-Rollback.ps1` | Removes every rule created by the allow script (matching the prefix `"Spark Remote Desktop"`). |
| `scripts/policies/registry/SparkRegistry-ReservedNamespace.reg` | Pre-creates the reserved `HKLM\Software\Spark` values so compliance teams can bless the namespace ahead of time. |
| `scripts/policies/registry/SparkRegistry-Rollback.reg` | Deletes the entire `HKLM\Software\Spark` branch if you need to revert. |

Store these files in the same directory when distributing to customers so they can apply or roll them back without hunting for dependencies.

## Firewall Bundle

The `SparkFirewall-AllowOutbound.ps1` script is designed for unattended execution (GPO startup script, Intune remediation, or manual PowerShell session). Example usage:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
cd C:\SparkPolicyBundle
./SparkFirewall-AllowOutbound.ps1 -SparkServerHost console.example.com -Ports 443,6060 -Verbose
```

Key behaviors:

- Creates one outbound TCP allow rule per port. The rule is scoped to the provided FQDN via `-RemoteFqdn`, so it only covers the Spark control plane.
- Pins rules to `C:\ProgramData\Spark\Spark.exe` by default. Override `-ProgramPath` if you relocated the agent.
- Passing `-Force` recreates rules if they already exist (handy for updating ports or hostnames).
- Rules are profile-agnostic (`Domain`, `Private`, `Public`) and keep inbound traffic blocked.

### Rollback

```powershell
cd C:\SparkPolicyBundle
./SparkFirewall-Rollback.ps1 -RulePrefix "Spark Remote Desktop" -Verbose
```

The rollback script finds every firewall rule whose `DisplayName` starts with the prefix and removes it. Safe to run multiple times; it simply reports when nothing matches.

## Registry Bundle

Import the reserved namespace file to create the Spark policy keys before the agent installs:

```powershell
reg import C:\SparkPolicyBundle\SparkRegistry-ReservedNamespace.reg
```

Before importing, edit the file so `InstallPath`, `Version`, and `ConfigChecksum` align with the values you intend to deploy. Example checksum placeholders use thirty-two zeroes; replace this with the SHA-256 of your `config.json` if you already generated it.

### Rollback

```powershell
reg import C:\SparkPolicyBundle\SparkRegistry-Rollback.reg
```

This deletes `HKLM\Software\Spark` entirely. Set the environment variable `SPARK_PRESERVE_REGISTRY=1` before uninstalling the agent if you prefer to keep the keys for forensics (see `docs/registry-footprint.md`).

## Operational Playbook

1. **Stage & hash the bundle** – Distribute the four files as a zip, publish checksums, and have customers verify with `Get-FileHash`.
2. **Apply in a maintenance window** – Run the firewall script first so devices can reach the control plane immediately after install. Follow with the registry import.
3. **Validate** – Use `Get-NetFirewallRule -DisplayName "Spark Remote Desktop*" | Format-List DisplayName, Enabled, RemoteFqdn, RemotePort` and `reg query HKLM\Software\Spark` to confirm state.
4. **Record evidence** – Capture the PowerShell transcript plus the output of `wevtutil qe Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` for audit trails.

## Troubleshooting Reverted Policies

Many SOC tools reapply baseline policies periodically. Use the following flow when a customer reports missing Spark firewall or registry entries:

1. **Detect drift automatically** – Schedule `Get-NetFirewallRule` and `reg query` checks via the agent watchdog or customer RMM. Alert when rules or keys disappear.
2. **Check GPO precedence** – Run `gpresult /h c:\temp\gp.html` on an affected endpoint. If another GPO rewrites firewall rules, import the Spark scripts as a higher-precedence Computer Configuration startup script.
3. **Verify security suite exclusions** – Some EDR products remove rules tagged with unknown programs. Configure the suite to trust `C:\ProgramData\Spark\Spark.exe` or use the `-ProgramPath $null` switch so rules are not program-scoped.
4. **Intune remediation** – Wrap the allow script as a remediation script with detection logic that checks for the required rules/keys. Intune can reapply them whenever drift occurs.
5. **Rollback safely** – If a change fails compliance review, run the rollback scripts, capture event logs, and open a ticket with SOC. The bundles leave no residual files beyond the firewall rules and registry key they manage.

Document these steps in customer runbooks so security teams know exactly how to recover if automated tools revert Spark allowances.
