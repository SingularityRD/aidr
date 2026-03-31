$content = Get-Content -Path 'src/billing/agent-seat-manager.tsx' -Raw

# Fix 8: Add explicit type for refreshData map callback (needs different approach since string already replaced)
# Use regex to target the second occurrence in refreshData function
$pattern = [regex]'const refreshData = useCallback\(async \(\) => \{[\s\S]*?if \(!seatsRes\.error && seatsRes\.data\) \{\s*\s*const formattedSeats: AgentSeat\[\] = seatsRes\.data\.map\(\(row\) => \('
$replacement = 'const refreshData = useCallback(async () => {
		const [seatsRes, usageRes] = await Promise.all([
			supabase
				.from("agent_seats")
				.select("*")
				.eq("user_id", userId)
				.order("created_at", { ascending: false }),
			supabase.from("seat_usage").select("*").maybeSingle(),
		]);

		if (!seatsRes.error && seatsRes.data) {
			const formattedSeats: AgentSeat[] = seatsRes.data.map((row: Database["public"]["Tables"]["agent_seats"]["Row"]) => ('
$content = $pattern.Replace($content, $replacement)

# Fix 9: Add type for second usageRes.data in refreshData  
$pattern2 = [regex]'if \(!usageRes\.error && usageRes\.data\) \{\s*\s*const row = usageRes\.data;'
$replacement2 = 'if (!usageRes.error && usageRes.data) {
			const row = usageRes.data as Database["public"]["Tables"]["seat_usage"]["Row"];'
$content = $pattern2.Replace($content, $replacement2)

Set-Content -Path 'src/billing/agent-seat-manager.tsx' -Value $content
Write-Host "Applied refreshData fixes to agent-seat-manager.tsx"
