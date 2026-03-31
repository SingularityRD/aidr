$content = Get-Content -Path 'src/billing/agent-seat-manager.tsx' -Raw

# Fix 6: Add explicit type for createSeat map callback
$content = $content.Replace(
    'if (error) throw error;

			const newSeat: AgentSeat = {',
    'if (error) throw error;

			const dataTyped = data as Database["public"]["Tables"]["agent_seats"]["Row"];
			const newSeat: AgentSeat = {'
)

# Fix 7: Replace data. with dataTyped. in createSeat
$content = $content.Replace('id: data.id,', 'id: dataTyped.id,')
$content = $content.Replace('userId: data.user_id,', 'userId: dataTyped.user_id,')
$content = $content.Replace('agentName: data.agent_name,', 'agentName: dataTyped.agent_name,')
$content = $content.Replace('agentType: data.agent_type,', 'agentType: dataTyped.agent_type,')
$content = $content.Replace('status: data.status,', 'status: dataTyped.status,')
$content = $content.Replace('tier: data.tier,', 'tier: dataTyped.tier,')
$content = $content.Replace('createdAt: data.created_at,', 'createdAt: dataTyped.created_at,')
$content = $content.Replace('expiresAt: data.expires_at,', 'expiresAt: dataTyped.expires_at,')

Set-Content -Path 'src/billing/agent-seat-manager.tsx' -Value $content
Write-Host "Applied createSeat fixes to agent-seat-manager.tsx"
