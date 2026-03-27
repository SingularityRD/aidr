import { Link, Outlet, useNavigate } from "react-router-dom";
import { signOut } from "./session";

export function Layout() {
	const navigate = useNavigate();

	return (
		<div className="app">
			<header className="topbar">
				<div className="brand">Singularity AIDR</div>
				<nav className="nav">
					<Link to="/agents">Agents</Link>
					<Link to="/api-keys">API Keys</Link>
				</nav>
				<button
					className="button button-secondary"
					type="button"
					onClick={async () => {
						await signOut();
						navigate("/login");
					}}
				>
					Sign out
				</button>
			</header>
			<main className="main">
				<Outlet />
			</main>
		</div>
	);
}

