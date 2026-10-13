import { useState } from "react";
import { englishT, type Translate, useRichT, useT } from "../../i18n/I18nProvider";

export type DirectoryAuthority = {
	enabled: boolean;
	directory_id: string | null;
	break_glass_user_ids: string[];
};

export type DirectoryAuthorityRequest =
	| {
			action: "enable";
			directoryId: string;
			breakGlassUserIds: string[];
			adoptExisting: boolean;
			removeUnmanaged: boolean;
	  }
	| { action: "disable" };

type Owner = { userId: string; email: string };
type Props = {
	authority: DirectoryAuthority;
	/** Directories that currently hold an active provisioning credential. */
	directories: string[];
	owners: Owner[];
	currentUserId: string;
	busy: boolean;
	onChange: (request: DirectoryAuthorityRequest) => Promise<boolean>;
};

// The server requires the break-glass list to equal the active owner set and
// caps it at two (emergency-access accounts), so the panel never lets an owner
// pick a subset that the database would refuse.
const MAX_BREAK_GLASS_OWNERS = 2;

function ownerLabel(
	owner: Owner | undefined,
	userId: string,
	currentUserId: string,
	t: Translate = englishT,
): string {
	const name = owner?.email || userId;
	return userId === currentUserId ? t("da.you", { name }) : name;
}

/** Tenant toggle for directory-authoritative membership (off by default). */
export function DirectoryAuthorityPanel({
	authority,
	directories,
	owners,
	currentUserId,
	busy,
	onChange,
}: Props) {
	const t = useT();
	const richT = useRichT();
	const [selected, setSelected] = useState("");
	const [adoptExisting, setAdoptExisting] = useState(false);
	const [removeUnmanaged, setRemoveUnmanaged] = useState(false);
	const [confirming, setConfirming] = useState(false);

	const directory = directories.includes(selected) ? selected : (directories[0] ?? "");
	// Fall back to the caller only when the member list is unavailable; the
	// server still verifies the list against every active owner.
	const breakGlass = owners.length > 0 ? owners.map((owner) => owner.userId) : [currentUserId];
	const tooManyOwners = breakGlass.length > MAX_BREAK_GLASS_OWNERS;
	const canEnable = !busy && directory !== "" && !tooManyOwners;

	async function submit(request: DirectoryAuthorityRequest) {
		if (await onChange(request)) {
			setConfirming(false);
			setAdoptExisting(false);
			setRemoveUnmanaged(false);
		}
	}

	return (
		<section className="card" aria-labelledby="directory-authority-heading">
			<h2 id="directory-authority-heading">{t("da.title")}</h2>
			<p className="muted">{t("da.lead")}</p>

			{authority.enabled ? (
				<>
					<p role="status">
						{richT("da.onLine", {
							state: <strong>{t("da.on")}</strong>,
							directory: <span className="mono">{authority.directory_id}</span>,
						})}
					</p>
					<p className="small">{t("da.breakGlass")}</p>
					<ul className="small">
						{authority.break_glass_user_ids.map((userId) => (
							<li key={userId}>
								{ownerLabel(
									owners.find((owner) => owner.userId === userId),
									userId,
									currentUserId,
									t,
								)}
							</li>
						))}
					</ul>
					<p className="muted small">{t("da.locked")}</p>
					{confirming ? (
						<div className="row">
							<span className="small" role="status">
								{t("da.confirmOff")}
							</span>
							<button
								className="button button-danger button-sm"
								type="button"
								disabled={busy}
								onClick={() => void submit({ action: "disable" })}
							>
								{t("da.confirmOffButton")}
							</button>
							<button
								className="button button-secondary button-sm"
								type="button"
								disabled={busy}
								onClick={() => setConfirming(false)}
							>
								{t("common.cancel")}
							</button>
						</div>
					) : (
						<button
							className="button button-secondary"
							type="button"
							disabled={busy}
							onClick={() => setConfirming(true)}
						>
							{t("da.turnOff")}
						</button>
					)}
				</>
			) : (
				<>
					<p role="status">{richT("da.offLine", { state: <strong>{t("da.off")}</strong> })}</p>
					{directories.length === 0 ? (
						<p className="muted small">{t("da.noDirectory")}</p>
					) : (
						<>
							<label className="label" htmlFor="directory-authority-directory">
								{t("da.directory")}
							</label>
							<select
								id="directory-authority-directory"
								className="input mono"
								value={directory}
								onChange={(event) => {
									setSelected(event.target.value);
									setConfirming(false);
								}}
							>
								{directories.map((id) => (
									<option key={id} value={id}>
										{id}
									</option>
								))}
							</select>
						</>
					)}
					<p className="small" style={{ marginTop: 10 }}>
						{t("da.breakGlassAll")}
					</p>
					<ul className="small">
						{breakGlass.map((userId) => (
							<li key={userId}>
								{ownerLabel(
									owners.find((owner) => owner.userId === userId),
									userId,
									currentUserId,
									t,
								)}
							</li>
						))}
					</ul>
					{tooManyOwners ? (
						<p className="notice notice-warning" role="note">
							{t("da.tooMany")}
						</p>
					) : null}
					<label className="label">
						<input
							type="checkbox"
							checked={adoptExisting}
							onChange={(event) => setAdoptExisting(event.target.checked)}
						/>{" "}
						{t("da.adopt")}
					</label>
					<p className="muted small">{t("da.adoptHint")}</p>
					<label className="label">
						<input
							type="checkbox"
							checked={removeUnmanaged}
							onChange={(event) => setRemoveUnmanaged(event.target.checked)}
						/>{" "}
						{t("da.remove")}
					</label>
					<p className="muted small">{t("da.removeHint")}</p>
					{confirming ? (
						<div className="row">
							<span className="small" role="status">
								{richT("da.confirmOn", { directory: <span className="mono">{directory}</span> })}
							</span>
							<button
								className="button button-danger button-sm"
								type="button"
								disabled={!canEnable}
								onClick={() =>
									void submit({
										action: "enable",
										directoryId: directory,
										breakGlassUserIds: breakGlass,
										adoptExisting,
										removeUnmanaged,
									})
								}
							>
								{t("da.confirmOnButton")}
							</button>
							<button
								className="button button-secondary button-sm"
								type="button"
								disabled={busy}
								onClick={() => setConfirming(false)}
							>
								{t("common.cancel")}
							</button>
						</div>
					) : (
						<button
							className="button"
							type="button"
							disabled={!canEnable}
							onClick={() => setConfirming(true)}
						>
							{t("da.turnOn")}
						</button>
					)}
				</>
			)}
		</section>
	);
}
