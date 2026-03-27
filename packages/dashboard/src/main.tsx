import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createBrowserRouter, redirect } from "react-router-dom";
import { Layout } from "./ui/Layout";
import { AgentsPage } from "./ui/pages/AgentsPage";
import { ApiKeysPage } from "./ui/pages/ApiKeysPage";
import { AgentDetailPage } from "./ui/pages/AgentDetailPage";
import { LoginPage } from "./ui/pages/LoginPage";
import { getSession } from "./ui/session";
import "./styles.css";

const router = createBrowserRouter([
	{
		path: "/",
		element: <Layout />,
		loader: async () => {
			const session = await getSession();
			if (!session) throw redirect("/login");
			return null;
		},
		children: [
			{ index: true, loader: async () => redirect("/agents") },
			{ path: "agents", element: <AgentsPage /> },
			{ path: "agents/:agentId", element: <AgentDetailPage /> },
			{ path: "api-keys", element: <ApiKeysPage /> },
		],
	},
	{
		path: "/login",
		element: <LoginPage />,
	},
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
	<React.StrictMode>
		<RouterProvider router={router} />
	</React.StrictMode>,
);

