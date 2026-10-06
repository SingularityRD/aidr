import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const native = path.join(root, 'deploy/fleet/windows/Invoke-AidrResponseAction.ps1');
const psString = (value) => `'${value.replaceAll("'", "''")}'`;

test('Windows native response: persistent pause, disjoint dual-stack isolation and exact rollback (mocked OS only)', { skip: process.platform !== 'win32' }, (context) => {
  // Shared Windows TEMP may grant other accounts DeleteChild. Keep this isolated
  // fixture under the private profile, away from the real response-control path.
  const fixture = mkdtempSync(path.join(homedir(), '.aidr-response-action-test-'));
  const harness = path.join(fixture, 'check.ps1');
  const source = String.raw`
$ErrorActionPreference = 'Stop'
. NATIVE_PATH
$script:checks = 0
$script:rules = @()
$script:admin = $true
$script:enabled = 'True'
$script:merge = 'True'
$script:mutations = 0
$script:failCreate = 0
$script:createCalls = 0
$script:failRemove = $false
$script:appearRoot = $null
function Check($Value, $Label) { if (-not $Value) { throw ('FAILED: ' + $Label) }; $script:checks++ }
function Fails([scriptblock]$Action, [string]$Code) {
  try { & $Action | Out-Null } catch { Check ($_.Exception.Message -ceq $Code) ($Code + ': ' + $_.Exception.Message); return }
  throw ('Expected failure: ' + $Code)
}
function Test-AidrResponseAdmin { return $script:admin }
function Get-Service { [CmdletBinding()]param($Name) return [pscustomobject]@{ Status = 'Running' } }
function Get-NetFirewallProfile {
  [CmdletBinding()]param($PolicyStore)
  foreach ($name in @('Domain', 'Private', 'Public')) { [pscustomobject]@{ Name = $name; Enabled = $script:enabled; AllowLocalFirewallRules = $script:merge; AllowInboundRules = 'True'; DisabledInterfaceAliases = @() } }
}
function Get-NetFirewallRule {
  [CmdletBinding()]param([switch]$All, $PolicyStore, [switch]$TracePolicyStore)
  if ($PolicyStore -ceq 'ActiveStore' -and $null -ne $script:appearRoot) { [IO.Directory]::CreateDirectory($script:appearRoot) | Out-Null; $script:appearRoot = $null }
  return @($script:rules)
}
function Get-NetFirewallAddressFilter { [CmdletBinding()]param($AssociatedNetFirewallRule) return $AssociatedNetFirewallRule.AddressFilter }
function Get-NetFirewallPortFilter { [CmdletBinding()]param($AssociatedNetFirewallRule) return $AssociatedNetFirewallRule.PortFilter }
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param($AssociatedNetFirewallRule) return $AssociatedNetFirewallRule.ApplicationFilter }
function Get-NetFirewallServiceFilter { [CmdletBinding()]param($AssociatedNetFirewallRule) return [pscustomobject]@{ Service = 'Any' } }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()]param($AssociatedNetFirewallRule) return [pscustomobject]@{ InterfaceAlias = 'Any' } }
function Get-NetFirewallInterfaceTypeFilter { [CmdletBinding()]param($AssociatedNetFirewallRule) return [pscustomobject]@{ InterfaceType = 'Any' } }
function Get-NetFirewallSecurityFilter { [CmdletBinding()]param($AssociatedNetFirewallRule) return $AssociatedNetFirewallRule.SecurityFilter }
function New-NetFirewallRule {
  [CmdletBinding()]param($Name, $DisplayName, $Group, $Description, $PolicyStore, $Enabled, $Profile, $Direction, $Action, $Protocol, $LocalAddress, $RemoteAddress, $LocalPort, $RemotePort, $Program, $Service, $InterfaceAlias, $InterfaceType, $EdgeTraversalPolicy = 'Block', $Authentication, $Encryption, [bool]$OverrideBlockRules)
  $script:createCalls++
  if ($script:failCreate -eq $script:createCalls) { throw 'mock_create_failure' }
  Check ($PolicyStore -ceq 'PersistentStore') 'only persistent own rules created'
  $script:rules += [pscustomobject]@{ Name = $Name; Group = $Group; Description = $Description; Enabled = $Enabled; Profile = $Profile; Direction = $Direction; Action = $Action; Owner = ''; EdgeTraversalPolicy = $EdgeTraversalPolicy; PolicyStoreSourceType = 'Local'; PrimaryStatus = 'OK'; EnforcementStatus = 'Full'; Platform = @(); PolicyAppId = ''; PackageFamilyName = '';
    AddressFilter = [pscustomobject]@{ LocalAddress = @($LocalAddress); RemoteAddress = @($RemoteAddress) };
    PortFilter = [pscustomobject]@{ Protocol = $Protocol; LocalPort = $LocalPort; RemotePort = $RemotePort; DynamicTarget = 'Any' };
    ApplicationFilter = [pscustomobject]@{ Program = $Program; Package = '' };
    SecurityFilter = [pscustomobject]@{ Authentication = $Authentication; Encryption = $Encryption; OverrideBlockRules = $OverrideBlockRules; LocalUser = 'Any'; RemoteUser = 'Any'; RemoteMachine = 'Any' } }
  $script:mutations++
}
function Remove-NetFirewallRule {
  [CmdletBinding()]param($Name, $PolicyStore)
  Check ($Name -notmatch '[*?]' -and $PolicyStore -ceq 'PersistentStore') 'rollback exact name only'
  if ($script:failRemove) { throw 'mock_remove_failure' }
  $script:rules = @($script:rules | Where-Object Name -CNE $Name)
  $script:mutations++
}
function New-Request([string]$Type, [string]$Id, $Rollback, [string]$Root) {
  $identity = [pscustomobject]@{ tenant_id = '11111111-1111-4111-8111-111111111111'; agent_id = '22222222-2222-4222-8222-222222222222'; installation_id = 'test-installation' }
  $expires = [DateTimeOffset]::UtcNow.AddHours(1).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
  $created = [DateTimeOffset]::UtcNow.AddSeconds(-1).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
  $command = [pscustomobject]@{ id = $Id; command_type = $Type; expires_at = $expires; attempt = 1; rollback_of = $Rollback }
  $delivery = [pscustomobject]@{ alg = 'ed25519'; key_id = 'fixture'; sig_b64 = ('A' * 86 + '=='); payload = [pscustomobject]@{ schema_version = 1; purpose = 'aidr.fleet-response.command'; key_id = 'fixture'; tenant_id = $identity.tenant_id; agent_id = $identity.agent_id; installation_id = $identity.installation_id; key_hash = ('a' * 64); id = $Id; command_type = $Type; payload = [pscustomobject]@{}; rollback_of = $Rollback; created_at = $created; expires_at = $expires; attempt = 1 } }
  return [pscustomobject]@{ schema_version = 1; operation = 'execute'; identity = $identity; command = $command; delivery = $delivery; state_root = $Root; recovery_addresses = @('203.0.113.10', '2001:db8::10') }
}
function Inspect-Request($Source) { return [pscustomobject]@{ schema_version = 1; operation = 'inspect_removal'; identity = $Source.identity; command = $null; delivery = $null; state_root = $Source.state_root; recovery_addresses = @() } }
$base = FIXTURE_PATH
$pauseId = '33333333-3333-4333-8333-333333333333'
$resumeId = '44444444-4444-4444-8444-444444444444'
$isolateId = '55555555-5555-4555-8555-555555555555'
$releaseId = '66666666-6666-4666-8666-666666666666'
$ips = @(Get-AidrResponseIp '203.0.113.10'; Get-AidrResponseIp '2001:db8::10')
Check ((@(Get-AidrResponseComplement $ips 32) -join ',') -ceq '0.0.0.0-203.0.113.9,203.0.113.11-255.255.255.255') 'IPv4 complement'
Check ((@(Get-AidrResponseComplement $ips 128) -join ',') -ceq '::-2001:db8::f,2001:db8::11-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') 'IPv6 complement'
$bounds = @(Get-AidrResponseIp '0.0.0.0'; Get-AidrResponseIp '0.0.0.1'; Get-AidrResponseIp '255.255.255.255'; Get-AidrResponseIp '::'; Get-AidrResponseIp 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
Check ((@(Get-AidrResponseComplement $bounds 32) -join ',') -ceq '0.0.0.2-255.255.255.254') 'adjacent IPv4 bounds no overflow'
Check ((@(Get-AidrResponseComplement $bounds 128) -join ',') -ceq '::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe') 'IPv6 bounds no overflow'
Check ((@(Get-AidrResponseComplement @((Get-AidrResponseIp '203.0.113.10')) 128) -join ',') -ceq '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') 'IPv4-only policy blocks IPv6'
foreach ($bad in @('localhost', 'Any', '10.1', '010.0.0.1', '203.0.113.0/24', '::ffff:192.0.2.1', 'fe80::1%1')) { Fails { Get-AidrResponseIp $bad } 'invalid_recovery_address' }
Check ((Get-AidrResponseAddressSet @('203.0.113.8/30')) -ceq (Get-AidrResponseAddressSet @('203.0.113.8-203.0.113.11'))) 'native address normalization'

$pause = New-Request 'agent_pause' $pauseId $null (Join-Path $base 'pause')
$pause.recovery_addresses = @()
$pause.operation = 'dry_run'
Check ((Invoke-AidrResponseAction $pause).observed -eq $false -and -not [IO.Directory]::Exists($pause.state_root)) 'dry run has no state writes'
$pause.operation = 'execute'
Check ((Invoke-AidrResponseAction $pause).ok) 'persist signed pause'
$barrierPath = Join-Path $pause.state_root 'barrier.json'
$barrier = Read-AidrResponseBarrier $barrierPath $pause.identity
Check ($barrier.command_id -ceq $pauseId -and $barrier.command_signed.sig_b64 -ceq $pause.delivery.sig_b64) 'barrier contains exact signed delivery'
$pause.operation = 'verify'; Check ((Invoke-AidrResponseAction $pause).observed) 'independent pause observation'
$pause.operation = 'execute'; Check ((Invoke-AidrResponseAction $pause).evidence.state -ceq 'idempotent') 'pause retry idempotent'
Fails { Invoke-AidrResponseAction (Inspect-Request $pause) } 'response_removal_active_pause'
$wrong = New-Request 'agent_resume' $resumeId $isolateId $pause.state_root
Fails { Invoke-AidrResponseAction $wrong } 'response_rollback_mismatch'
Check ([IO.File]::Exists($barrierPath)) 'wrong rollback preserves pause'
$resume = New-Request 'agent_resume' $resumeId $pauseId $pause.state_root
Check ((Invoke-AidrResponseAction $resume).ok) 'resume removes matching barrier'
$resume.operation = 'verify'; Check ((Invoke-AidrResponseAction $resume).observed -and -not [IO.File]::Exists($barrierPath)) 'resume needs its own receipt and absence'
Check ((Invoke-AidrResponseAction (Inspect-Request $resume)).removable) 'applied resume receipt permits removal'
$pause.operation = 'execute'; Fails { Invoke-AidrResponseAction $pause } 'response_command_replay'
Check (-not [IO.File]::Exists($barrierPath)) 'rolled-back command cannot recreate pause'
$missingReceipt = New-Request 'agent_resume' $releaseId $pauseId (Join-Path $base 'empty')
Initialize-AidrResponseStateRoot $missingReceipt.state_root
$missingReceipt.operation = 'verify'; Fails { Invoke-AidrResponseAction $missingReceipt } 'response_action_not_observed'
Check ((Invoke-AidrResponseAction (Inspect-Request $missingReceipt)).removable) 'empty native state with zero owned rules removable'
$inspectEmpty = Inspect-Request $missingReceipt
$held = [IO.FileStream]::new((Join-Path $missingReceipt.state_root 'action.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 4096, [IO.FileOptions]::DeleteOnClose)
try { Fails { Invoke-AidrResponseAction $inspectEmpty } 'response_action_busy' } finally { $held.Dispose() }
$beforeInspect = $script:mutations
Check ((Invoke-AidrResponseAction $inspectEmpty).removable -and $script:mutations -eq $beforeInspect) 'inspection observes without OS actions'
Check (-not [IO.File]::Exists((Join-Path $missingReceipt.state_root 'action.lock'))) 'inspection releases transient native lock'
$race = New-Request 'agent_pause' $pauseId $null (Join-Path $base 'root-race')
$script:appearRoot = $race.state_root
Fails { Invoke-AidrResponseAction (Inspect-Request $race) } 'response_removal_state_changed'

$network = New-Request 'network_isolate' $isolateId $null (Join-Path $base 'network')
$script:admin = $false
Fails { Invoke-AidrResponseAction $network } 'response_requires_administrator'
Check ($script:rules.Count -eq 0 -and -not [IO.Directory]::Exists($network.state_root)) 'nonadmin refusal precedes changes'
$script:admin = $true
$script:merge = 'False'; Fails { Invoke-AidrResponseAction $network } 'firewall_policy_unsupported'; $script:merge = 'True'
$script:enabled = 'False'; Fails { Invoke-AidrResponseAction $network } 'firewall_policy_unsupported'; $script:enabled = 'True'
Check ($script:rules.Count -eq 0) 'unsupported profile policy adds no rules'
$script:rules = @([pscustomobject]@{ Name = 'Customer.Block'; Group = 'Customer'; Enabled = 'True'; Action = 'Block'; AddressFilter = [pscustomobject]@{ RemoteAddress = @('203.0.113.0/24') } })
Fails { Invoke-AidrResponseAction $network } 'firewall_recovery_policy_conflict'
Check ($script:rules.Count -eq 1 -and $script:rules[0].Name -ceq 'Customer.Block') 'conflicting customer rule is preserved'
$script:rules = @([pscustomobject]@{ Name = 'Customer.Bypass'; Group = 'Customer'; Enabled = 'True'; Action = 'Allow'; SecurityFilter = [pscustomobject]@{ OverrideBlockRules = 'True' } })
Fails { Invoke-AidrResponseAction $network } 'firewall_bypass_policy_unsupported'
$script:rules = @()
Check ((Invoke-AidrResponseAction $network).ok -and $script:rules.Count -eq 6) 'six own native isolation rules'
Check (@($script:rules | Where-Object { $_.Action -eq 'Block' -and $_.AddressFilter.RemoteAddress -contains 'Any' }).Count -eq 0) 'never block Any plus allow exception'
$expectedSpecs = @(Get-AidrResponseRules $network.identity $isolateId $ips)
$reordered = [pscustomobject]@{ installation_id = $network.identity.installation_id; agent_id = $network.identity.agent_id; tenant_id = $network.identity.tenant_id }
Check ((@(Get-AidrResponseRules $reordered $isolateId $ips).Name -join ',') -ceq ($expectedSpecs.Name -join ',')) 'identity order cannot change ownership'
foreach ($rule in $script:rules) {
  $set = @(Get-AidrResponseAddressIntervals $rule.AddressFilter.RemoteAddress)
  foreach ($ip in $ips) {
    $inside = @($set | Where-Object { $_.Bits -eq $ip.Bits -and $_.Start -le $ip.Number -and $_.End -ge $ip.Number }).Count -gt 0
    Check ($inside -eq ($rule.Action -eq 'Allow')) 'recovery allows and blocks never overlap'
  }
}
$network.operation = 'verify'; Check ((Invoke-AidrResponseAction $network).observed) 'independent effective isolation observation'
$before = $script:mutations
$originalRemote = $script:rules[0].AddressFilter.RemoteAddress
$script:rules[0].AddressFilter.RemoteAddress = @('Any')
Fails { Invoke-AidrResponseAction $network } 'firewall_owned_filter_mismatch'
Check ($script:mutations -eq $before) 'verify never repairs wrong filter'
$script:rules[0].AddressFilter.RemoteAddress = $originalRemote
$script:rules[0].PortFilter.DynamicTarget = 'ProximityApps'
Fails { Invoke-AidrResponseAction $network } 'firewall_owned_filter_mismatch'
$script:rules[0].PortFilter.DynamicTarget = 'Any'
$script:rules[0].PolicyStoreSourceType = 'GroupPolicy'
Fails { Invoke-AidrResponseAction $network } 'firewall_owned_rule_mismatch'
$script:rules[0].PolicyStoreSourceType = 'Local'
$script:rules[0].EnforcementStatus = 'LocalFirewallRulesDisallowed'
Fails { Invoke-AidrResponseAction $network } 'firewall_owned_rule_not_enforced'
$script:rules[0].EnforcementStatus = 'Full'
$script:rules[0].PolicyAppId = 'RestrictedApp'
Fails { Invoke-AidrResponseAction $network } 'firewall_owned_filter_mismatch'
$script:rules[0].PolicyAppId = ''
$script:rules[0].Enabled = 'False'; Fails { Invoke-AidrResponseAction $network } 'firewall_owned_rule_mismatch'; $script:rules[0].Enabled = 'True'
$network.operation = 'execute'; Check ((Invoke-AidrResponseAction $network).evidence.state -ceq 'idempotent' -and $script:mutations -eq $before) 'isolate retry creates no duplicates'
$reuse = New-Request 'network_isolate' $isolateId $null $network.state_root; $reuse.recovery_addresses = @('203.0.113.11')
Fails { Invoke-AidrResponseAction $reuse } 'response_command_reuse'
Fails { Invoke-AidrResponseAction (Inspect-Request $network) } 'response_removal_active_state'
$release = New-Request 'network_release' $releaseId $isolateId $network.state_root
$release.identity = $reordered
$oldName = $script:rules[0].Name; $script:rules[0].Name = $oldName + '.renamed'
Fails { Invoke-AidrResponseAction $release } 'firewall_unexpected_owned_rule'
Check ($script:rules.Count -eq 6) 'renamed rule prevents false release success'
$script:rules[0].Name = $oldName
Check ((Invoke-AidrResponseAction $release).ok -and $script:rules.Count -eq 0) 'exact owned rollback removes six rules'
$release.operation = 'verify'; Check ((Invoke-AidrResponseAction $release).observed) 'release receipt and dual-store absence observed'
Check ((Invoke-AidrResponseAction (Inspect-Request $release)).removable) 'applied release receipt permits removal'
$network.operation = 'execute'; Fails { Invoke-AidrResponseAction $network } 'response_command_replay'
Check ($script:rules.Count -eq 0) 'rolled-back isolate cannot recreate rules'

$partial = New-Request 'network_isolate' $isolateId $null (Join-Path $base 'partial')
$script:createCalls = 0; $script:failCreate = 3
Fails { Invoke-AidrResponseAction $partial } 'native_action_outcome_unknown'
Check ($script:rules.Count -eq 0) 'partial-create cleanup touches only own created rules'
$script:failCreate = 0
$partial.operation = 'verify'; Fails { Invoke-AidrResponseAction $partial } 'firewall_isolation_not_observed'
Fails { Invoke-AidrResponseAction (Inspect-Request $partial) } 'response_removal_active_state'

$foreign = New-Request 'agent_pause' $pauseId $null (Join-Path $base 'foreign')
Initialize-AidrResponseStateRoot $foreign.state_root
[IO.File]::WriteAllText((Join-Path $foreign.state_root 'pause-state.json'), '{}')
Fails { Invoke-AidrResponseAction (Inspect-Request $foreign) } 'invalid_response_request'
$inspect = Inspect-Request $missingReceipt
$ownGroup = $expectedSpecs[0].Group
$script:rules = @([pscustomobject]@{ Name = $ownGroup + '.renamed'; Group = $ownGroup })
Fails { Invoke-AidrResponseAction $inspect } 'response_removal_owned_rules_present'
$script:rules = @([pscustomobject]@{ Name = 'Customer.Rule'; Group = 'Customer.Firewall' })
Check ((Invoke-AidrResponseAction $inspect).removable) 'customer firewall rules preserved and outside ownership'
$script:rules = @()

$badScope = New-Request 'agent_pause' $pauseId $null (Join-Path $base 'bad-scope')
$badScope.delivery.payload.agent_id = '77777777-7777-4777-8777-777777777777'
Fails { Invoke-AidrResponseAction $badScope } 'response_delivery_mismatch'
Check (-not [IO.Directory]::Exists($badScope.state_root)) 'signed scope mismatch no side effects'
Fails { Assert-AidrResponseStatePath $base -CurrentUser } 'response_state_path_mismatch'
$nativeText = [IO.File]::ReadAllText(NATIVE_PATH)
Check ($nativeText -notmatch 'Set-NetFirewallProfile|Disable-NetFirewall|Invoke-Expression') 'no global firewall/config executable pipeline'
[Console]::Out.WriteLine((@{ checks = $script:checks; version = $PSVersionTable.PSVersion.ToString(); mutations = $script:mutations } | ConvertTo-Json -Compress))
`;
  writeFileSync(harness, source.replaceAll('NATIVE_PATH', psString(native)).replaceAll('FIXTURE_PATH', psString(fixture)), 'utf8');
  try {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', harness], { cwd: root, encoding: 'utf8', timeout: 60_000, windowsHide: true });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const evidence = JSON.parse(result.stdout.trim());
    assert.ok(evidence.checks >= 65, `expected focused checks, got ${JSON.stringify(evidence)}`);
    assert.match(evidence.version, /^5\.1\./);
    context.diagnostic(`${evidence.checks} assertions on PowerShell ${evidence.version}; OS firewall operations mocked`);
  } finally { rmSync(fixture, { recursive: true, force: true }); }
});

test('native main rejects alternate state roots without any action (WhatIf)', { skip: process.platform !== 'win32' }, () => {
  const request = { schema_version: 1, operation: 'inspect_removal', identity: { tenant_id: '11111111-1111-4111-8111-111111111111', agent_id: '22222222-2222-4222-8222-222222222222', installation_id: 'test-installation' }, command: null, delivery: null, state_root: root, recovery_addresses: [] };
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', native, '-WhatIf'], { cwd: root, input: JSON.stringify(request), encoding: 'utf8', timeout: 15_000, windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { ok: false, code: 'response_state_path_mismatch' });
});
