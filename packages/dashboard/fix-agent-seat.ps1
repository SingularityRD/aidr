$content = Get-Content -Path 'src/billing/agent-seat-manager.tsx' -Raw

# Fix 1: Add Database import
$content = $content.Replace('import { supabase } from "../lib/supabase";', 'import { supabase } from "../lib/supabase";
import type { Database } from "../lib/database.types";')

# Fix 2: Export the interfaces
$content = $content.Replace('interface AgentSeat {', 'export interface AgentSeat {')
$content = $content.Replace('interface SeatEntitlements {', 'export interface SeatEntitlements {')
$content = $content.Replace('interface BillingInfo {', 'export interface BillingInfo {')

Set-Content -Path 'src/billing/agent-seat-manager.tsx' -Value $content
Write-Host "Applied fixes to agent-seat-manager.tsx"
