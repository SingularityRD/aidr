import { createContext, useContext, useEffect, useState } from "react";

type Theme = "light" | "dark";

interface ThemeContextType {
	theme: Theme;
	toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
	const [theme, setTheme] = useState<Theme>("light");
	const [mounted, setMounted] = useState(false);

	useEffect(() => {
		setMounted(true);
		try {
			const stored = localStorage.getItem("theme") as Theme | null;
			if (stored === "light" || stored === "dark") {
				setTheme(stored);
			} else if (
				typeof window.matchMedia === "function" &&
				window.matchMedia("(prefers-color-scheme: dark)").matches
			) {
				setTheme("dark");
			}
		} catch {
			// Private browsing/storage-disabled contexts keep the default theme.
		}
	}, []);

	useEffect(() => {
		if (mounted) {
			document.documentElement.setAttribute("data-theme", theme);
			try {
				localStorage.setItem("theme", theme);
			} catch {
				// Theme still applies to the current session if storage is unavailable.
			}
		}
	}, [theme, mounted]);

	const toggleTheme = () => {
		setTheme((prev: Theme) => (prev === "light" ? "dark" : "light"));
	};

	return <ThemeContext.Provider value={{ theme, toggleTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
	const context = useContext(ThemeContext);
	if (context === undefined) {
		return { theme: "light" as Theme, toggleTheme: () => {} };
	}
	return context;
}
