import { useT } from "../i18n/I18nProvider";
import { MoonIcon, SunIcon } from "./icons";
import { useTheme } from "./ThemeProvider";

export function ThemeToggle() {
	const { theme, toggleTheme } = useTheme();
	const t = useT();
	const label = theme === "light" ? t("theme.toDark") : t("theme.toLight");

	return (
		<button
			type="button"
			onClick={toggleTheme}
			className="theme-toggle"
			aria-label={label}
			title={label}
		>
			{theme === "light" ? <MoonIcon /> : <SunIcon />}
		</button>
	);
}
