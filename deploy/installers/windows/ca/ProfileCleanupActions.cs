// Machine-wide removal of hook registrations (every user profile), without a
// privileged process ever editing files inside a user's profile.
//
// The uninstalling user's connectors are removed by `aidr uninstall`
// (AidrUninstallForUser). For every other profile the final uninstall registers
// the permanently installed cleanup\Remove-AidrUserRegistrations.ps1 as an
// Active Setup component: Windows runs it once per user at their next logon, as
// that user. Installing AIDR again removes the registration first, so a
// reinstalled product's hooks are never touched (the script also does nothing
// while aidr.exe exists).
using System;
using System.Globalization;
using Microsoft.Win32;
using WixToolset.Dtf.WindowsInstaller;

namespace SingularityAidr.Installer
{
    public static class ProfileCleanupActions
    {
        // A fixed component id, separate from the per-version setup component.
        public const string ComponentKey = @"Software\Microsoft\Active Setup\Installed Components\{6F0A3D2E-91B4-4C77-A5E8-2B9D1C4E7F30}";
        public const string ScriptRelativePath = @"cleanup\Remove-AidrUserRegistrations.ps1";

        /// <summary>The Active Setup command line for the cleanup script in installFolder.</summary>
        public static string StubPath(string systemFolder, string installFolder)
        {
            string powershell = System.IO.Path.Combine(systemFolder, @"WindowsPowerShell\v1.0\powershell.exe");
            string script = System.IO.Path.Combine(installFolder, ScriptRelativePath);
            return "\"" + powershell + "\" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File \"" + script + "\"";
        }

        /// <summary>Active Setup runs a component again when its Version is higher than the user's copy.</summary>
        public static string Version(DateTime utc)
        {
            return utc.ToString("yyyy,MMdd,HHmm,ss", CultureInfo.InvariantCulture);
        }

        /// <summary>Deferred, as LocalSystem, final uninstall only: register the per-user cleanup.</summary>
        [CustomAction]
        public static ActionResult RegisterProfileCleanup(Session session)
        {
            CustomActionData data = session.CustomActionData;
            string installFolder = data.ContainsKey("install") ? data["install"] : "";
            string systemFolder = data.ContainsKey("system") ? data["system"] : "";
            if (installFolder.Length == 0 || systemFolder.Length == 0 || installFolder.IndexOf('"') >= 0 || systemFolder.IndexOf('"') >= 0)
            {
                session.Log("Singularity AIDR: other profiles' hook cleanup not registered (no install folder).");
                return ActionResult.Success;
            }
            try
            {
                using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).CreateSubKey(ComponentKey))
                {
                    key.SetValue("", "Singularity AIDR cleanup", RegistryValueKind.String);
                    key.SetValue("StubPath", StubPath(systemFolder, installFolder), RegistryValueKind.String);
                    key.SetValue("Version", Version(DateTime.UtcNow), RegistryValueKind.String);
                    key.SetValue("IsInstalled", 1, RegistryValueKind.DWord);
                }
                session.Log("Singularity AIDR: every other user's AIDR hook registrations are removed at their next sign-in.");
            }
            catch (Exception error)
            {
                session.Log("Singularity AIDR: other profiles' hook cleanup not registered (" + error.GetType().Name + ").");
            }
            return ActionResult.Success;
        }

        /// <summary>Deferred, as LocalSystem, on install: a reinstalled product owns the registrations again.</summary>
        [CustomAction]
        public static ActionResult UnregisterProfileCleanup(Session session)
        {
            try
            {
                RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).DeleteSubKeyTree(ComponentKey, false);
            }
            catch (Exception error)
            {
                session.Log("Singularity AIDR: earlier cleanup registration not removed (" + error.GetType().Name + ").");
            }
            return ActionResult.Success;
        }
    }
}
