# Kalıcı durum formatı ve güvenli kurtarma

Yeni hücreler `aidr-state-v2` kullanır. AES-256-GCM doğrulaması tenant, namespace, key, sürüm, şifreleme anahtarı kimliği ve son geçerlilik zamanını bağlar. Veritabanındaki `expires` alanını değiştirmek onay süresini uzatamaz; okuma `STATE_INTEGRITY` ile kapanır.

Önceki RC formatında `expires` doğrulanmıyordu. Bu nedenle v1 hücreleri v2 koduyla otomatik kabul edilmez veya yeniden imzalanmaz. Eski kayıt okunmaya çalışıldığında işlem kapanır; kaynak kayıt silinmez. Bu sürümde genel v1 → v2 dönüştürme aracı bulunmuyor. Kurulmuş v1 veritabanı varsa yükseltme öncesi kontrollü geçiş gerekir.

1. Hizmeti durdurun; veritabanının, gerekli eski anahtarların ve bağımsız audit/policy anchor'larının erişimi sınırlandırılmış yedeğini alın. Geri dönüş işlemini ayrı ortamda doğrulayın.
2. Eski durumu yalnız onaylı eski sürümün izole, ağsız ve salt okunur bir kopyasında inceleyin. Hücrelerin v1 şifreleme doğrulaması ve audit zinciri kontrolü, açık `expires` değerinin güvenilir olduğunu kanıtlamaz.
3. Geçişte kalıcı request ID'leri, dispatch durumları, CAS sürümleri/tombstone'ları, policy checkpoint'leri, iptaller ve audit geçmişi korunmalıdır. Silerek yeni bir DB başlatmak tekrar gönderim ve rollback güvencelerini sıfırlar. Bağımsız doğrulanmış kaynaklara dayanan kuruma özel geçiş aracını bu invariants ile test edin.
4. Eski kısa ömürlü onayları, bekleyen OIDC girişlerini ve portal oturumlarını geçersiz kılın; yeni sürümde yeniden kimlik doğrulama/onay alın. Kalıcı güvenlik geçmişini geçici giriş kayıtlarıyla birlikte temizlemeyin.

`STATE_INTEGRITY` aynı zamanda bozulma veya yanlış anahtar belirtir. Bu hatada eski format fallback'i açmayın. Yedek/anahtar/anchor doğrulamasını tamamlamadan hizmeti yeniden açmayın. Tam eski bir snapshot'ın geri alınmasını algılamak için bağımsız güncel anchor gereklidir.

## Karar audit anahtarı, segment rotation ve sayfalı export

- `PersistentAuditJournal` head kaydında `keyId` tutar. Açılışta ve her append'de head'in son kaydı (veya boş segmenti açan rotation kaydı) yapılandırılan anahtarla doğrulanır. Farklı `keyId` veya farklı anahtar baytı `AUDIT_KEY_MISMATCH` ile başlatmayı ve append'i reddeder; zincir değişmez. `keyId` taşımayan eski head'ler son kayıt üzerinden doğrulanır ve ilk append'de bağlanır.
- Anahtar değiştirmek için eski anahtarı bir kez `audit.rotateFrom` olarak verin (`PersistentAuditJournal.rotate/open`). Eski segment, eski anahtarla imzalı kapanış checkpoint'i ile kapanır; yeni segment `<logId>:s<n>` adıyla sıfırdan başlar. `aidr-audit-rotation-v1` kaydı eski head hash'ini, yeni logId/keyId'yi ve önceki rotation hash'ini bağlar ve iki anahtarla da imzalanır. Doğrulama: eski segment `verifyAudit(records, rotation.closing, eskiAnahtar)`, yeni segment `verifyAudit(records, checkpoint(), yeniAnahtar)`, bağlantı `verifyAuditRotation(rotation, eskiAnahtar, yeniAnahtar, öncekiRotation)`. Eski segmentlerin anahtarlarını saklama süresi boyunca koruyun.
- `records()` bellek içi tam export'tur ve 100.000 kayıtta `AUDIT_EXPORT_LIMIT` ile sınırlı kalır. Olay incelemesi için `page(fromSequence, limit<=1000, {logId, upTo})` kullanın: önce checkpoint alın, her sayfaya aynı `upTo` değerini verin ve sayfaları `AuditChainVerifier` ile sırayla doğrulayın. Boşluk, tekrar, sıra değişikliği veya eksik son sayfa doğrulamayı kalıcı olarak başarısız yapar; eşzamanlı append'ler sabitlenmiş export'u etkilemez.
- Quota pencereleri (`quotas`) süresi dolunca her `consume` çağrısında en fazla 64 satırlık sınırlı partilerle fiziksel olarak silinir; geçerli pencere asla silinmez. Replay (`approvals`, `dispatch`), saat/policy (`internal`) ve audit namespace'lerine genel TTL uygulanmaz.
