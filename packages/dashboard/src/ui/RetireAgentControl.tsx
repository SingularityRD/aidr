import { useState } from "react";
import { useT } from "../i18n/I18nProvider";
import { lifecycleErrorKey, retireAgent } from "../lib/agent-lifecycle";

/**
 * Two-step "Retire" action for one agent. The first click only asks for
 * confirmation; the second calls the agent-lifecycle function, which
 * re-checks role and AAL2. Nothing changes locally until the server confirms.
 */
export function RetireAgentControl({
	tenantId,
	agentId,
	onRetired,
}: {
	tenantId: string;
	agentId: string;
	onRetired: () => void;
}) {
	const t = useT();
	const [confirming, setConfirming] = useState(false);
	const [busy, setBusy] = useState(false);
	const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);

	if (!confirming) {
		return (
			<span>
				<button
					className="button button-secondary button-sm"
					type="button"
					onClick={() => {
						setMessage(null);
						setConfirming(true);
					}}
				>
					{t("agents.retire.action")}
				</button>
				{message ? (
					<span
						className={message.tone === "error" ? "small" : "small muted"}
						role={message.tone === "error" ? "alert" : "status"}
						style={{ marginLeft: 8 }}
					>
						{message.text}
					</span>
				) : null}
			</span>
		);
	}
	return (
		<div className="notice notice-warning" role="group" aria-label={t("agents.retire.action")}>
			<div className="small">{t("agents.retire.confirm")}</div>
			<div className="row" style={{ marginTop: 8, gap: 8 }}>
				<button
					className="button button-sm"
					type="button"
					disabled={busy}
					onClick={async () => {
						setBusy(true);
						const result = await retireAgent(tenantId, agentId);
						setBusy(false);
						setConfirming(false);
						if (!result.ok) {
							setMessage({ tone: "error", text: t(lifecycleErrorKey(result.code)) });
							return;
						}
						setMessage({
							tone: "success",
							text: t("agents.retire.done", { count: result.value.revokedKeys }),
						});
						onRetired();
					}}
				>
					{busy ? t("agents.retire.busy") : t("agents.retire.confirmButton")}
				</button>
				<button
					className="button button-secondary button-sm"
					type="button"
					disabled={busy}
					onClick={() => setConfirming(false)}
				>
					{t("agents.retire.cancel")}
				</button>
			</div>
		</div>
	);
}
