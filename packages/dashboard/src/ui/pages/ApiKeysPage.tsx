import { useEffect, useMemo, useState } from "react";
import { supabase } from "../../lib/supabase";
import { generateApiKey, sha256Hex } from "../../lib/crypto";

type ApiKeyRow = {
	id: string;
	label: string | null;
	key_hash: string;
	revoked: boolean;
	created_at: string;
};

export function ApiKeysPage() {
	const [keys, setKeys] = useState<ApiKeyRow[]>([]);
	const [label, setLabel] = useState("");
	const [createdKey, setCreatedKey] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const trimmedLabel = useMemo(() => label.trim(), [label]);

	async function load() {
		const res = await supabase
			.from("api_keys")
			.select("id,label,key_hash,revoked,created_at")
			.order("created_at", { ascending: false });
		if (res.error) setError(res.error.message);
		else setKeys((res.data ?? []) as ApiKeyRow[]);
	}

	useEffect(() => {
		load();
	}, []);

	return (
		<div className="stack">
			<div className="card">
				<h1>API Keys</h1>
				<p className="muted">
					API keys are stored as SHA-256 hashes only. The plaintext key is shown once at creation.
				</p>

				<label className="label">
					Label (optional)
					<input
						className="input"
						value={label}
						onChange={(e) => setLabel(e.target.value)}
						placeholder="work-laptop, build-server, etc."
					/>
				</label>

				<div className="row">
					<button
						className="button"
						type="button"
						disabled={busy}
						onClick={async () => {
							setBusy(true);
							setError(null);
							setCreatedKey(null);
							try {
								const session = (await supabase.auth.getSession()).data.session;
								if (!session?.user) {
									setError("Not signed in.");
									return;
								}

								const plaintext = generateApiKey();
								const hash = await sha256Hex(plaintext);

								const { error: insErr } = await supabase.from("api_keys").insert({
									user_id: session.user.id,
									label: trimmedLabel || null,
									key_hash: hash,
								});

								if (insErr) {
									setError(insErr.message);
									return;
								}

								setCreatedKey(plaintext);
								setLabel("");
								await load();
							} finally {
								setBusy(false);
							}
						}}
					>
						Generate key
					</button>
					<button
						className="button button-secondary"
						type="button"
						onClick={async () => {
							await load();
						}}
					>
						Refresh
					</button>
				</div>

				{createdKey ? (
					<div className="notice">
						<div className="muted small">Copy this key now (shown once):</div>
						<div className="mono">{createdKey}</div>
					</div>
				) : null}
				{error ? <div className="notice notice-danger">{error}</div> : null}
			</div>

			<div className="card">
				<table className="table">
					<thead>
						<tr>
							<th>Label</th>
							<th>Created</th>
							<th>Status</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{keys.map((k) => (
							<tr key={k.id}>
								<td>{k.label ?? <span className="muted">(no label)</span>}</td>
								<td className="mono">{new Date(k.created_at).toLocaleString()}</td>
								<td>{k.revoked ? "revoked" : "active"}</td>
								<td className="right">
									<button
										className="button button-secondary"
										type="button"
										disabled={k.revoked}
										onClick={async () => {
											setBusy(true);
											setError(null);
											try {
												const { error: upErr } = await supabase
													.from("api_keys")
													.update({ revoked: true })
													.eq("id", k.id);
												if (upErr) setError(upErr.message);
												await load();
											} finally {
												setBusy(false);
											}
										}}
									>
										Revoke
									</button>
								</td>
							</tr>
						))}
						{keys.length === 0 ? (
							<tr>
								<td colSpan={4} className="muted">
									No keys yet.
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</div>
	);
}

