// Company connection custom actions of the Singularity AIDR MSI (see
// AidrInstallerActions.csproj). The enrollment code is a one-time secret:
// it travels from the hidden MSI property ENROLLMENT_CODE through hidden
// CustomActionData (HideTarget) into a file only the installing user can open,
// and `aidr setup` deletes that file after use. It is never put on a command
// line and never written to the msiexec log.
using System;
using System.Globalization;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using WixToolset.Dtf.WindowsInstaller;

namespace SingularityAidr.Installer
{
    public static class EnrollmentActions
    {
        // The same rules as packages/cli/src/utils/installer-enrollment.ts;
        // deploy/installers/installers.test.mjs fails when the two differ.
        public const string UrlPattern = @"^https://[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?$";
        public const string CodePattern = @"^aidr_enroll_[A-Za-z0-9_-]{43}$";
        public const int MaxUrlLength = 512;
        public const string HandoffDirectory = ".singularity-aidr";
        public const string HandoffFile = "installer-enrollment.json";
        public const string HandoffFormat = "aidr-installer-enrollment/1";

        /// <summary>"" when the pair is acceptable, otherwise "url" or "code".</summary>
        public static string Problem(string url, string code)
        {
            if (url.Length == 0 && code.Length == 0) return "url";
            if (url.Length > 0 && (url.Length > MaxUrlLength || !Regex.IsMatch(url, UrlPattern, RegexOptions.CultureInvariant))) return "url";
            if (code.Length > 0 && !Regex.IsMatch(code, CodePattern, RegexOptions.CultureInvariant)) return "code";
            return "";
        }

        private static string Clean(string value)
        {
            return (value ?? "").Trim();
        }

        /// <summary>Wizard (immediate): sets AIDR_ENROLLMENT_ERROR to "", "url" or "code".</summary>
        [CustomAction]
        public static ActionResult ValidateEnrollmentInput(Session session)
        {
            session["AIDR_ENROLLMENT_ERROR"] = Problem(Clean(session["ENROLLMENT_URL"]), Clean(session["ENROLLMENT_CODE"]));
            return ActionResult.Success;
        }

        /// <summary>Deferred, impersonated as the installing user: write the handoff file.</summary>
        [CustomAction]
        public static ActionResult WriteEnrollmentHandoff(Session session)
        {
            CustomActionData data = session.CustomActionData;
            string url = Clean(data.ContainsKey("url") ? data["url"] : "");
            string code = Clean(data.ContainsKey("code") ? data["code"] : "");
            string problem = Problem(url, code);
            if (problem.Length > 0)
            {
                session.Log(problem == "url"
                    ? "Singularity AIDR: company connection not saved: ENROLLMENT_URL must be an https:// address."
                    : "Singularity AIDR: company connection not saved: ENROLLMENT_CODE is not a Singularity AIDR enrollment code.");
                return ActionResult.Failure;
            }
            SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
            if (user == null || user.IsWellKnown(WellKnownSidType.LocalSystemSid))
            {
                // Never for LocalSystem: there is no interactive user to connect.
                session.Log("Singularity AIDR: company connection skipped (no interactive user).");
                return ActionResult.Success;
            }
            try
            {
                WriteUserOnly(HandoffPath(), Json(url, code), user);
            }
            catch (Exception error)
            {
                session.Log("Singularity AIDR: company connection could not be saved (" + error.GetType().Name + ").");
                return ActionResult.Failure;
            }
            session.Log("Singularity AIDR: company connection saved for aidr setup (" + (code.Length > 0 ? "with" : "without") + " an enrollment code).");
            return ActionResult.Success;
        }

        /// <summary>Rollback, impersonated: remove a handoff file this install wrote.</summary>
        [CustomAction]
        public static ActionResult RemoveEnrollmentHandoff(Session session)
        {
            try
            {
                string path = HandoffPath();
                if (File.Exists(path)) File.Delete(path);
            }
            catch (Exception error)
            {
                session.Log("Singularity AIDR: the company connection file could not be removed (" + error.GetType().Name + ").");
            }
            return ActionResult.Success;
        }

        private static string HandoffPath()
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrEmpty(profile)) throw new IOException("no user profile");
            return Path.Combine(Path.Combine(profile, HandoffDirectory), HandoffFile);
        }

        // Both values matched the patterns above: no quote, backslash or control
        // character can reach the JSON text.
        private static string Json(string url, string code)
        {
            string created = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            return "{\"format\":\"" + HandoffFormat + "\",\"control_plane_url\":\"" + url +
                "\",\"enrollment_code\":\"" + code + "\",\"created_at\":\"" + created + "\"}\n";
        }

        private static bool IsLink(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }

        /// <summary>
        /// Create the file with a protected DACL that grants only the user (no
        /// inherited entries, so not even Administrators by default), then move
        /// it into place. A link in place of the folder or the file is refused.
        /// </summary>
        private static void WriteUserOnly(string path, string text, SecurityIdentifier user)
        {
            string directory = Path.GetDirectoryName(path);
            Directory.CreateDirectory(directory);
            if (IsLink(directory)) throw new IOException("the .singularity-aidr folder is a link");
            FileSecurity security = new FileSecurity();
            security.SetOwner(user);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
            string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            byte[] bytes = new UTF8Encoding(false).GetBytes(text);
            try
            {
                using (FileStream stream = new FileStream(temp, FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, security))
                {
                    stream.Write(bytes, 0, bytes.Length);
                }
                if (File.Exists(path))
                {
                    if (IsLink(path)) throw new IOException("the handoff file is a link");
                    File.Delete(path);
                }
                File.Move(temp, path);
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
        }
    }
}
