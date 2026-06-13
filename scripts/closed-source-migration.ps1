# Singularity AIDR — Kapalı Kaynak Geçiş Scripti
# Bu script, açık kaynaktan kapalı kaynağa geçiş için gerekli adımları içerir.
# ÇALIŞTIRMADAN ÖNCE: npm/yayıncı hesabınızda oturum açtığınızdan emin olun.

Write-Host "=== Singularity AIDR - Kapalı Kaynak Geçiş Scripti ===" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# ADIM 1: GitHub Repo'yu Archive'le
# ============================================================
Write-Host "ADIM 1: GitHub Repo Archive" -ForegroundColor Yellow
Write-Host "  Şu adrese gidip repo'yu archive'leyin:"
Write-Host "  https://github.com/SingularityRD/aidr/settings"
Write-Host "  Settings -> Danger Zone -> Archive this repository"
Write-Host ""

# ============================================================
# ADIM 2: npm Paketlerini Deprecate Et (npm login gerektirir)
# ============================================================
Write-Host "ADIM 2: npm Paketlerini Deprecate Etme" -ForegroundColor Yellow
Write-Host "  npm login yaptığınızdan emin olun!"
Write-Host ""

$packages = @(
    "@singularityrd/aidr-core",
    "@singularityrd/aidr-claude-code",
    "@singularityrd/aidr-openclaw",
    "@singularityrd/aidr-opencode",
    "@singularityrd/aidr-cli",
    "@singularityrd/aidr-sdk",
    "@singularityrd/aidr-dashboard"
)

$message = "⚠️ This package has moved to a private/commercial license. " +
           "Singularity AIDR is now a closed-source product. " +
           "Visit https://aidr.singularityrd.com for the latest version."

foreach ($pkg in $packages) {
    $cmd = "npm deprecate $pkg '$message'"
    Write-Host "  Çalıştırılacak: $cmd" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  Deprecate komutlarını çalıştırmak için yukarıdaki komutları terminalde çalıştırın."
Write-Host ""

# ============================================================
# ADIM 3: VS Code Extension Kaldırma
# ============================================================
Write-Host "ADIM 3: VS Code Extension Kaldırma" -ForegroundColor Yellow
Write-Host "  1. https://marketplace.visualstudio.com/manage adresine gidin"
Write-Host "  2. 'aidr-cursor' extension'unu bulun"
Write-Host "  3. Unpublish yapın"
Write-Host ""

# ============================================================
# ADIM 4: Yeni Private Repo Kurulumu
# ============================================================
Write-Host "ADIM 4: Yeni Private Repo Kurulumu" -ForegroundColor Yellow
Write-Host "  1. GitHub'da yeni PRIVATE repo oluşturun (örn. SingularityRD/aidr-private)"
Write-Host "  2. Mevcut kodu yeni repo'ya push edin:"
Write-Host "     git remote remove origin"
Write-Host "     git remote add origin https://github.com/SingularityRD/aidr-private.git"
Write-Host "     git push -u origin master"
Write-Host "  3. GitHub Packages'ı etkinleştirin:"
Write-Host "     Settings -> Security -> Actions -> General -> Read and write permissions"
Write-Host ""

# ============================================================
# ADIM 5: GitHub Packages için npmrc Yapılandırması
# ============================================================
Write-Host "ADIM 5: GitHub Packages (Private npm Registry) Ayarları" -ForegroundColor Yellow
Write-Host "  Her package.json'a ekle:"
Write-Host '    "publishConfig": {'
Write-Host '      "registry": "https://npm.pkg.github.com/"'
Write-Host '    }'
Write-Host ""
Write-Host "  Kök dizine .npmrc ekle:"
Write-Host "    @singularityrd:registry=https://npm.pkg.github.com/"
Write-Host "    //npm.pkg.github.com/:_authToken=\${GITHUB_TOKEN}"
Write-Host ""

# ============================================================
# ADIM 6: CI/CD Güncelleme
# ============================================================
Write-Host "ADIM 6: CI/CD Güncelleme" -ForegroundColor Yellow
Write-Host "  GitHub Actions workflow'larını private repo'ya taşıyın."
Write-Host "  npm publish adımlarını GitHub Packages'a yönlendirin."
Write-Host "  VSIX build/publish adımlarını güncelleyin."
Write-Host ""

# ============================================================
# ADIM 7: VSIX Özel Dağıtım
# ============================================================
Write-Host "ADIM 7: VSIX Özel Dağıtım" -ForegroundColor Yellow
Write-Host "  VS Code extension'ı private VSIX olarak dağıtın:"
Write-Host "  pnpm -C packages/extension run package:vsix"
Write-Host "  -> dist/aidr-cursor-*.vsix dosyasını özel bir URL'den dağıtın"
Write-Host ""

Write-Host "=== Geçiş için gerekli tüm adımlar yukarıda listelenmiştir. ===" -ForegroundColor Cyan
