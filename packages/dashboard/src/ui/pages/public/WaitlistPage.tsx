import { useMemo, useState } from "react";
import { supabase } from "../../../lib/supabase";

export function WaitlistPage() {
	const [name, setName] = useState("");
	const [email, setEmail] = useState("");
	const [company, setCompany] = useState("");
	const [message, setMessage] = useState("");
	const [busy, setBusy] = useState(false);
	const [status, setStatus] = useState<string | null>(null);

	const payload = useMemo(
		() => ({
			name: name.trim() || null,
			email: email.trim(),
			company: company.trim() || null,
			message: message.trim() || null,
		}),
		[name, email, company, message],
	);

	const canSubmit = payload.email.includes("@");

	return (
		<div className="stack">
			<div className="card">
				<h1>Waitlist</h1>
				<p className="muted">
					Get early access updates and pilot invites. We’ll prioritize teams actively running AI
					agents in production.
				</p>
			</div>

			<div className="card">
				<label className="label">
					Name
					<input className="input" value={name} onChange={(e) => setName(e.target.value)} />
				</label>
				<label className="label">
					Work email
					<input
						className="input"
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						placeholder="you@company.com"
						autoComplete="email"
					/>
				</label>
				<label className="label">
					Company
					<input className="input" value={company} onChange={(e) => setCompany(e.target.value)} />
				</label>
				<label className="label">
					What are you protecting?
					<textarea
						className="input"
						style={{ minHeight: 120, resize: "vertical" }}
						value={message}
						onChange={(e) => setMessage(e.target.value)}
						placeholder="Agent runtime, tools, risks, constraints…"
					/>
				</label>

				<div className="row">
					<button
						className="button"
						type="button"
						disabled={busy || !canSubmit}
						onClick={async () => {
							setBusy(true);
							setStatus(null);
							try {
								const res = await supabase.functions.invoke("waitlist-signup", {
									method: "POST",
									body: payload,
								});
								if (res.error) {
									setStatus(res.error.message);
									return;
								}
								setStatus("You're on the list. We'll reach out soon.");
								setName("");
								setEmail("");
								setCompany("");
								setMessage("");
							} finally {
								setBusy(false);
							}
						}}
					>
						Join waitlist
					</button>
				</div>

				{status ? <div className="notice">{status}</div> : null}
			</div>
		</div>
	);
}
