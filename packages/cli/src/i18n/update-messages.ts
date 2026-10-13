/**
 * `aidr update` output (en/tr). Kept next to the main CLI catalog so the
 * update command can change without touching the incident-command messages;
 * `{name}` marks a parameter. Command names, flags, file names and
 * configuration keys stay as they are in every locale.
 */
export const UPDATE_EN = {
	"update.notInstaller":
		"This copy of Singularity AIDR was not installed with the Windows or Linux installer, so 'aidr update' cannot replace it. Update it the way it was installed (npm package, Claude Code plugin, VSIX).",
	"update.unsupportedPlatform":
		"Singularity AIDR installers are offered for Windows and Linux (x64 and arm64); this machine is {platform}/{arch}.",
	"update.linuxRoot":
		"Run 'aidr update' as yourself, not as root or with sudo. It asks for your sudo password when it installs.",
	"update.mdm":
		"Singularity AIDR on this machine is managed by your IT department's device management ({source}). Updates arrive from there; 'aidr update' can only check (--check).",
	"update.mdmAuto": "Automatic updates are off: device management ({source}) updates this machine.",
	"update.noSource":
		"There is no update source. A managed device uses your organisation's portal after it is enrolled ('aidr setup'). Otherwise use the installer your administrator gave you: aidr update --from <file-or-https-url> (or set update.source).",
	"update.noKey":
		"Updates cannot be verified: no installer-catalog public key is set. Your administrator places it at {path} or sets update.catalog_public_keys. Nothing was downloaded or installed.",
	"update.keyInvalid":
		"The installer-catalog key in {source} is not a valid Ed25519 public key. Nothing was downloaded or installed.",
	"update.checking": "Checking {source} for a newer Singularity AIDR…",
	"update.sourcePortal": "your organisation's portal ({endpoint})",
	"update.upToDate": "Singularity AIDR is up to date (v{current}).",
	"update.available":
		"Singularity AIDR v{latest} is available (you have v{current}). To install it, run: aidr update",
	"update.releaseNotes": "Release notes: {url}",
	"update.older":
		"The update source offers v{latest}, which is older than the installed v{current}. Nothing to do; a deliberate downgrade needs --allow-downgrade.",
	"update.downgradeRefused":
		"Refusing to go back from v{current} to v{latest}. If your administrator asked for this rollback, run the command again with --allow-downgrade.",
	"update.noInstallerForPlatform":
		"The signed catalog for v{latest} has no installer for {platform}.",
	"update.formatMismatch":
		"The available installer is a {format} file, but Singularity AIDR on this machine was installed as {kind}. Install the matching {kind} package with your package manager, or ask your administrator to publish it.",
	"update.autoOff": "Automatic updates are off (update.auto: off).",
	"update.downloading": "Downloading {file} ({size} MB)…",
	"update.verified": "Signed catalog and SHA-256 verified ({sha256}).",
	"update.confirmPrompt":
		"Install Singularity AIDR v{latest} in place of v{current}? The current version is kept and put back if the new one does not pass 'aidr verify'.",
	"update.notConfirmed": "{reason} Nothing was installed.",
	"update.installing": "Installing v{latest} ({kind})…",
	"update.done":
		"Singularity AIDR v{latest} is installed and passed 'aidr verify'. Restart your AI tools so they load it.",
	"update.rolledBack":
		"The new version did not pass the checks ({reason}). v{current} was put back and passed its integrity check; your AI tools stay protected by it.",
	"update.rolledBackPackage":
		"The package manager still lists v{latest}. To make that consistent, reinstall the v{current} installer, or run 'aidr update' again once the problem is fixed.",
	"update.rollbackFailed":
		"The new version did not pass the checks ({reason}) and putting v{current} back did not finish: {detail}. Reinstall Singularity AIDR from its installer now; until then tool calls may not be inspected.",
	"update.lockBusy": "Another 'aidr update' is running. Try again when it has finished.",
	"update.snapshotInvalid":
		"The installed Singularity AIDR failed its own integrity check, so it cannot be kept as the fallback copy ({detail}). Reinstall it from the installer instead. Nothing was changed.",
	"update.stagedInvalid":
		"The new bundle inside the installer failed its integrity check against the installed release key ({detail}). Nothing was changed.",
	"update.tarInvalid": "The installer archive could not be used ({detail}). Nothing was changed.",
	"update.needsElevation":
		"The Windows installer needs administrator rights. Open the terminal with 'Run as administrator' and run 'aidr update' again. Nothing was changed.",
	"update.privilegeDenied":
		"Installing needs administrator rights (sudo) and they were not granted ({detail}). Nothing was changed.",
	"update.installerFailed": "The installer stopped with an error ({detail}). Nothing was changed.",
	"update.error.no_trusted_key":
		"Updates cannot be verified: no installer-catalog public key is set. Nothing was downloaded or installed.",
	"update.error.signature_invalid":
		"The update catalog's signature does not match the installer-catalog key this machine trusts. Nothing was downloaded or installed. Tell your administrator: the catalog may have been altered, or the key was changed.",
	"update.error.pointer_invalid":
		"The update catalog is signed but its content is not valid. Nothing was downloaded or installed.",
	"update.error.catalog_invalid":
		"The update catalog is signed but its content is not valid. Nothing was downloaded or installed.",
	"update.error.digest_mismatch":
		"The downloaded installer does not match the SHA-256 in the signed catalog. It was deleted; nothing was installed.",
	"update.error.size_mismatch":
		"The downloaded installer does not have the size given in the signed catalog. It was deleted; nothing was installed.",
	"update.error.unauthorized":
		"Your organisation's portal did not accept this device's credential. Enroll the device again with 'aidr setup', or ask your administrator.",
	"update.error.entitlement_required":
		"Your organisation's licence does not allow downloads right now. Ask your administrator.",
	"update.error.not_published":
		"No installer has been published to your organisation's portal yet.",
	"update.error.rate_limited": "The portal is busy. Try again in a minute.",
	"update.error.source_unreachable":
		"The update source could not be reached{detail}. Check the network connection and try again.",
	"update.error.source_insecure":
		"Refusing an insecure address ({detail}): updates are downloaded only over https.",
	"update.error.catalog_not_found":
		"No signed catalog (manifest.json and manifest.json.sig) was found for the installer{detail}. Give its location with --catalog <file-or-url>.",
	"update.error.installer_not_in_catalog":
		"{detail} is not this machine's installer in the signed catalog. Nothing was installed.",
	"update.error.download_failed": "The installer download failed{detail}. Nothing was installed.",
	"update.error.server_error":
		"The update source answered with an error{detail}. Nothing was downloaded or installed.",
	"update.error.invalid_response":
		"The update source sent an answer that could not be read{detail}. Nothing was downloaded or installed.",
} as const;

export type UpdateMessageKey = keyof typeof UPDATE_EN;

export const UPDATE_TR: Record<UpdateMessageKey, string> = {
	"update.notInstaller":
		"Bu Singularity AIDR kopyası Windows ya da Linux kurulum dosyasıyla kurulmadığı için 'aidr update' onu güncelleyemez. Nasıl kurduysanız öyle güncelleyin (npm paketi, Claude Code eklentisi, VSIX).",
	"update.unsupportedPlatform":
		"Singularity AIDR kurulum dosyaları Windows ve Linux (x64 ve arm64) için sunulur; bu makine {platform}/{arch}.",
	"update.linuxRoot":
		"'aidr update' komutunu root olarak ya da sudo ile değil, kendi kullanıcınızla çalıştırın. Kurulum sırasında sudo parolanızı kendisi sorar.",
	"update.mdm":
		"Bu makinedeki Singularity AIDR, BT biriminizin cihaz yönetimi tarafından yönetiliyor ({source}). Güncellemeler oradan gelir; 'aidr update' yalnızca denetim yapabilir (--check).",
	"update.mdmAuto":
		"Otomatik güncelleme kapalı: bu makineyi cihaz yönetimi ({source}) güncelliyor.",
	"update.noSource":
		"Güncelleme kaynağı yok. Yönetilen bir cihaz, kaydı yapıldıktan sonra ('aidr setup') kurumunuzun portalını kullanır. Aksi hâlde yöneticinizin verdiği kurulum dosyasını kullanın: aidr update --from <dosya-ya-da-https-adresi> (ya da update.source değerini ayarlayın).",
	"update.noKey":
		"Güncellemeler doğrulanamıyor: kurulum kataloğu açık anahtarı ayarlanmamış. Yöneticiniz anahtarı {path} konumuna koyar ya da update.catalog_public_keys değerini ayarlar. Hiçbir şey indirilmedi ya da kurulmadı.",
	"update.keyInvalid":
		"{source} içindeki kurulum kataloğu anahtarı geçerli bir Ed25519 açık anahtarı değil. Hiçbir şey indirilmedi ya da kurulmadı.",
	"update.checking": "{source} üzerinde daha yeni bir Singularity AIDR aranıyor…",
	"update.sourcePortal": "kurumunuzun portalı ({endpoint})",
	"update.upToDate": "Singularity AIDR güncel (v{current}).",
	"update.available":
		"Singularity AIDR v{latest} sürümü yayımlandı (sizdeki sürüm v{current}). Kurmak için şunu çalıştırın: aidr update",
	"update.releaseNotes": "Sürüm notları: {url}",
	"update.older":
		"Güncelleme kaynağı v{latest} sürümünü sunuyor; bu, kurulu v{current} sürümünden eski. Yapılacak bir şey yok; bilerek eski sürüme dönmek için --allow-downgrade gerekir.",
	"update.downgradeRefused":
		"v{current} sürümünden v{latest} sürümüne geri dönülmüyor. Bu geri dönüşü yöneticiniz istediyse komutu --allow-downgrade ile yeniden çalıştırın.",
	"update.noInstallerForPlatform":
		"v{latest} sürümünün imzalı kataloğunda {platform} için kurulum dosyası yok.",
	"update.formatMismatch":
		"Sunulan kurulum dosyası {format} biçiminde, ama bu makinedeki Singularity AIDR {kind} olarak kurulmuş. Uygun {kind} paketini paket yöneticinizle kurun ya da yöneticinizden onu yayımlamasını isteyin.",
	"update.autoOff": "Otomatik güncelleme kapalı (update.auto: off).",
	"update.downloading": "{file} indiriliyor ({size} MB)…",
	"update.verified": "İmzalı katalog ve SHA-256 doğrulandı ({sha256}).",
	"update.confirmPrompt":
		"Singularity AIDR v{current} yerine v{latest} kurulsun mu? Şu anki sürüm saklanır ve yeni sürüm 'aidr verify' denetiminden geçemezse geri yüklenir.",
	"update.notConfirmed": "{reason} Hiçbir şey kurulmadı.",
	"update.installing": "v{latest} kuruluyor ({kind})…",
	"update.done":
		"Singularity AIDR v{latest} kuruldu ve 'aidr verify' denetiminden geçti. Yeni sürümü yüklemeleri için yapay zekâ araçlarınızı yeniden başlatın.",
	"update.rolledBack":
		"Yeni sürüm denetimlerden geçemedi ({reason}). v{current} geri yüklendi ve bütünlük denetiminden geçti; yapay zekâ araçlarınız onunla korunmaya devam ediyor.",
	"update.rolledBackPackage":
		"Paket yöneticisi hâlâ v{latest} sürümünü gösteriyor. Bunu düzeltmek için v{current} kurulum dosyasını yeniden kurun ya da sorun giderildikten sonra 'aidr update' komutunu yeniden çalıştırın.",
	"update.rollbackFailed":
		"Yeni sürüm denetimlerden geçemedi ({reason}) ve v{current} sürümünün geri yüklenmesi tamamlanamadı: {detail}. Singularity AIDR'yi hemen kurulum dosyasından yeniden kurun; o zamana kadar araç çağrıları denetlenmeyebilir.",
	"update.lockBusy": "Başka bir 'aidr update' çalışıyor. O bittikten sonra yeniden deneyin.",
	"update.snapshotInvalid":
		"Kurulu Singularity AIDR kendi bütünlük denetiminden geçemediği için yedek kopya olarak saklanamıyor ({detail}). Bunun yerine kurulum dosyasından yeniden kurun. Hiçbir şey değiştirilmedi.",
	"update.stagedInvalid":
		"Kurulum dosyasındaki yeni paket, kurulu sürüm anahtarına göre bütünlük denetiminden geçemedi ({detail}). Hiçbir şey değiştirilmedi.",
	"update.tarInvalid": "Kurulum arşivi kullanılamadı ({detail}). Hiçbir şey değiştirilmedi.",
	"update.needsElevation":
		"Windows kurulum dosyası yönetici yetkisi istiyor. Terminali 'Yönetici olarak çalıştır' ile açıp 'aidr update' komutunu yeniden çalıştırın. Hiçbir şey değiştirilmedi.",
	"update.privilegeDenied":
		"Kurulum için yönetici yetkisi (sudo) gerekiyor ve verilmedi ({detail}). Hiçbir şey değiştirilmedi.",
	"update.installerFailed":
		"Kurulum dosyası bir hatayla durdu ({detail}). Hiçbir şey değiştirilmedi.",
	"update.error.no_trusted_key":
		"Güncellemeler doğrulanamıyor: kurulum kataloğu açık anahtarı ayarlanmamış. Hiçbir şey indirilmedi ya da kurulmadı.",
	"update.error.signature_invalid":
		"Güncelleme kataloğunun imzası, bu makinenin güvendiği kurulum kataloğu anahtarıyla eşleşmiyor. Hiçbir şey indirilmedi ya da kurulmadı. Yöneticinize bildirin: katalog değiştirilmiş ya da anahtar değişmiş olabilir.",
	"update.error.pointer_invalid":
		"Güncelleme kataloğu imzalı ama içeriği geçerli değil. Hiçbir şey indirilmedi ya da kurulmadı.",
	"update.error.catalog_invalid":
		"Güncelleme kataloğu imzalı ama içeriği geçerli değil. Hiçbir şey indirilmedi ya da kurulmadı.",
	"update.error.digest_mismatch":
		"İndirilen kurulum dosyası imzalı katalogdaki SHA-256 değeriyle eşleşmiyor. Dosya silindi; hiçbir şey kurulmadı.",
	"update.error.size_mismatch":
		"İndirilen kurulum dosyasının boyutu imzalı katalogdakiyle aynı değil. Dosya silindi; hiçbir şey kurulmadı.",
	"update.error.unauthorized":
		"Kurumunuzun portalı bu cihazın kimlik bilgisini kabul etmedi. Cihazı 'aidr setup' ile yeniden kaydedin ya da yöneticinize başvurun.",
	"update.error.entitlement_required":
		"Kurumunuzun lisansı şu anda indirmeye izin vermiyor. Yöneticinize başvurun.",
	"update.error.not_published": "Kurumunuzun portalında henüz yayımlanmış bir kurulum dosyası yok.",
	"update.error.rate_limited": "Portal şu anda yoğun. Bir dakika sonra yeniden deneyin.",
	"update.error.source_unreachable":
		"Güncelleme kaynağına ulaşılamadı{detail}. Ağ bağlantısını denetleyip yeniden deneyin.",
	"update.error.source_insecure":
		"Güvenli olmayan adres reddedildi ({detail}): güncellemeler yalnızca https üzerinden indirilir.",
	"update.error.catalog_not_found":
		"Kurulum dosyası için imzalı katalog (manifest.json ve manifest.json.sig) bulunamadı{detail}. Konumunu --catalog <dosya-ya-da-adres> ile verin.",
	"update.error.installer_not_in_catalog":
		"{detail}, imzalı katalogda bu makinenin kurulum dosyası olarak geçmiyor. Hiçbir şey kurulmadı.",
	"update.error.download_failed": "Kurulum dosyası indirilemedi{detail}. Hiçbir şey kurulmadı.",
	"update.error.server_error":
		"Güncelleme kaynağı bir hatayla yanıt verdi{detail}. Hiçbir şey indirilmedi ya da kurulmadı.",
	"update.error.invalid_response":
		"Güncelleme kaynağından okunamayan bir yanıt geldi{detail}. Hiçbir şey indirilmedi ya da kurulmadı.",
};
