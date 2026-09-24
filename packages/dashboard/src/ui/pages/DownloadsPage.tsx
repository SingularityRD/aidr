import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { DownloadCenter } from "../../onboarding/DownloadCenter";

export function DownloadsPage() {
	const { currentTeam, isLoading } = useTeam();
	if (isLoading) {
		return (
			<div className="card" role="status">
				Checking team access…
			</div>
		);
	}
	return (
		<div className="stack">
			<div className="card">
				<h1>Downloads</h1>
				<p className="muted">
					Download a connector from the published release, verify its SHA-256 digest, install it,
					and connect it to {currentTeam ? <b>{currentTeam.name}</b> : "your team"}. A runtime shows
					as detected once one of its agents has checked in.
				</p>
				<div className="row" style={{ flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to="/onboarding">
						Back to onboarding
					</Link>
					<Link className="button button-secondary button-sm" to="/agents">
						View agents
					</Link>
				</div>
			</div>
			<DownloadCenter teamId={currentTeam?.id ?? null} />
		</div>
	);
}
