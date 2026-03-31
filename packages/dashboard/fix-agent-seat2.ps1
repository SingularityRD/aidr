$content = Get-Content -Path 'src/billing/agent-seat-manager.tsx' -Raw

# Fix 3: Add explicit type annotation for map callback at line 103
$content = $content.Replace(
    'const formattedSeats: AgentSeat[] = seatsRes.data.map((row) => ({',
    'const formattedSeats: AgentSeat[] = seatsRes.data.map((row: Database["public"]["Tables"]["agent_seats"]["Row"]) => ({'
)

# Fix 4: Add explicit type for usageRes.data first occurrence (line 118)
$pattern1 = [regex]'if \(!usageRes\.error && usageRes\.data\) \{\s*\s*const row = usageRes\.data;'
$replacement1 = 'if (!usageRes.error && usageRes.data) {
				const row = usageRes.data as Database["public"]["Tables"]["seat_usage"]["Row"];'
$content = $pattern1.Replace($content, $replacement1, 1)

# Fix 5: Add explicit type for billingRes.data (line 140)
$pattern2 = [regex]'if \(!billingRes\.error && billingRes\.data\) \{\s*\s*const row = billingRes\.data;'
$replacement2 = 'if (!billingRes.error && billingRes.data) {
				const row = billingRes.data as Database["public"]["Tables"]["subscriptions"]["Row"];'
$content = $pattern2.Replace($content, $replacement2, 1)

Set-Content -Path 'src/billing/agent-seat-manager.tsx' -Value $content
Write-Host "Applied additional fixes to agent-seat-manager.tsx"
