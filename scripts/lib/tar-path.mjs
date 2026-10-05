import path from "node:path";

/**
 * Path-argument rules for spawning `tar` portably.
 *
 * GNU tar (MSYS builds on Windows) treats `host:path` as a remote archive, so an
 * absolute `C:\...` passed to `-f` fails with "Cannot connect to C:", and it also
 * mishandles backslashes in `-C`. bsdtar (System32) accepts everything. The recipe
 * that works with both: pass the archive as a bare relative file name with `cwd`
 * set to its directory, and give `-C` forward slashes via this helper. On POSIX
 * this is an identity operation, so Linux and macOS behaviour is unchanged.
 */
export function tarDirectory(directory) {
	return path.sep === "/" ? directory : directory.split(path.sep).join("/");
}
