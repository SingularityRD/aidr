import { MoonIcon, SunIcon } from "./icons";
import { useTheme } from "./ThemeProvider";

export function DarkModeToggle() {
	const { theme, toggleTheme } = useTheme();

	return (
		<button
			type="button"
			onClick={toggleTheme}
			className="theme-toggle"
			aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
		>
			{theme === "light" ? <MoonIcon /> : <SunIcon />}
		</button>
	);
}
