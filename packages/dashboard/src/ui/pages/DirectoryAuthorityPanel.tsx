import { useState } from "react";

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

function ownerLabel(owner: Owner | undefined, userId: string, currentUserId: string): string {
	const name = owner?.email || userId;
	return userId === currentUserId ? `${name} (you)` : name;
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
			<h2 id="directory-authority-heading">Directory-authoritative membership</h2>
			<p className="muted">
				When on, a membership in this workspace grants access only if the selected SCIM directory
				provisions it with the same role. Manually added members, invitations and credentials for
				any other directory stop granting access. Owners are kept as named break-glass accounts so a
				directory outage or mass deprovisioning cannot lock the workspace out.
			</p>

			{authority.enabled ? (
				<>
					<p role="status">
						<strong>On</strong> — authoritative directory{" "}
						<span className="mono">{authority.directory_id}</span>.
					</p>
					<p className="small">Break-glass owners:</p>
					<ul className="small">
						{authority.break_glass_user_ids.map((userId) => (
							<li key={userId}>
								{ownerLabel(
									owners.find((owner) => owner.userId === userId),
									userId,
									currentUserId,
								)}
							</li>
						))}
					</ul>
					<p className="muted small">
						While the mode is on, owners cannot be added, removed or demoted. Turn it off first,
						make the owner change, then turn it on again. Turning it off is audited and requires
						multi-factor verification.
					</p>
					{confirming ? (
						<div className="row">
							<span className="small" role="status">
								Turn off? Manually added members could be granted access again.
							</span>
							<button
								className="button button-danger button-sm"
								type="button"
								disabled={busy}
								onClick={() => void submit({ action: "disable" })}
							>
								Confirm turn off
							</button>
							<button
								className="button button-secondary button-sm"
								type="button"
								disabled={busy}
								onClick={() => setConfirming(false)}
							>
								Cancel
							</button>
						</div>
					) : (
						<button
							className="button button-secondary"
							type="button"
							disabled={busy}
							onClick={() => setConfirming(true)}
						>
							Turn off directory-authoritative mode
						</button>
					)}
				</>
			) : (
				<>
					<p role="status">
						<strong>Off</strong> — manual memberships and every directory's credentials grant
						access.
					</p>
					{directories.length === 0 ? (
						<p className="muted small">
							Create an active provisioning credential with a directory identifier first.
						</p>
					) : (
						<>
							<label className="label" htmlFor="directory-authority-directory">
								Authoritative directory
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
						Break-glass owners (every active owner, at most two):
					</p>
					<ul className="small">
						{breakGlass.map((userId) => (
							<li key={userId}>
								{ownerLabel(
									owners.find((owner) => owner.userId === userId),
									userId,
									currentUserId,
								)}
							</li>
						))}
					</ul>
					{tooManyOwners ? (
						<p className="notice notice-warning" role="note">
							This workspace has more than two owners. Remove or demote owners until at most two
							remain; they become the break-glass accounts.
						</p>
					) : null}
					<label className="label">
						<input
							type="checkbox"
							checked={adoptExisting}
							onChange={(event) => setAdoptExisting(event.target.checked)}
						/>{" "}
						Treat existing SCIM-provisioned memberships as coming from this directory
					</label>
					<p className="muted small">
						Only choose this if no other directory ever provisioned this workspace. Otherwise leave
						it off and let the directory re-provision its users.
					</p>
					<label className="label">
						<input
							type="checkbox"
							checked={removeUnmanaged}
							onChange={(event) => setRemoveUnmanaged(event.target.checked)}
						/>{" "}
						Remove members this directory does not provision
					</label>
					<p className="muted small">
						Removal is permanent and audited, and revokes their API keys and enrollments. If left
						off, enabling is refused while such members exist and nothing changes.
					</p>
					{confirming ? (
						<div className="row">
							<span className="small" role="status">
								Make <span className="mono">{directory}</span> authoritative?
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
								Confirm turn on
							</button>
							<button
								className="button button-secondary button-sm"
								type="button"
								disabled={busy}
								onClick={() => setConfirming(false)}
							>
								Cancel
							</button>
						</div>
					) : (
						<button
							className="button"
							type="button"
							disabled={!canEnable}
							onClick={() => setConfirming(true)}
						>
							Turn on directory-authoritative mode
						</button>
					)}
				</>
			)}
		</section>
	);
}
