# Kalıcı durum formatı ve güvenli kurtarma

Yeni hücreler `aidr-state-v2` kullanır. AES-256-GCM doğrulaması tenant, namespace, key, sürüm, şifreleme anahtarı kimliği ve son geçerlilik zamanını bağlar. Veritabanındaki `expires` alanını değiştirmek onay süresini uzatamaz; okuma `STATE_INTEGRITY` ile kapanır.

Önceki RC formatında `expires` doğrulanmıyordu. Bu nedenle v1 hücreleri v2 koduyla otomatik kabul edilmez veya yeniden imzalanmaz. Eski kayıt okunmaya çalışıldığında işlem kapanır; kaynak kayıt silinmez. Bu sürümde genel v1 → v2 dönüştürme aracı bulunmuyor. Kurulmuş v1 veritabanı varsa yükseltme öncesi kontrollü geçiş gerekir.

1. Hizmeti durdurun; veritabanının, gerekli eski anahtarların ve bağımsız audit/policy anchor'larının erişimi sınırlandırılmış yedeğini alın. Geri dönüş işlemini ayrı ortamda doğrulayın.
2. Eski durumu yalnız onaylı eski sürümün izole, ağsız ve salt okunur bir kopyasında inceleyin. Hücrelerin v1 şifreleme doğrulaması ve audit zinciri kontrolü, açık `expires` değerinin güvenilir olduğunu kanıtlamaz.
3. Geçişte kalıcı request ID'leri, dispatch durumları, CAS sürümleri/tombstone'ları, policy checkpoint'leri, iptaller ve audit geçmişi korunmalıdır. Silerek yeni bir DB başlatmak tekrar gönderim ve rollback güvencelerini sıfırlar. Bağımsız doğrulanmış kaynaklara dayanan kuruma özel geçiş aracını bu invariants ile test edin.
4. Eski kısa ömürlü onayları, bekleyen OIDC girişlerini ve portal oturumlarını geçersiz kılın; yeni sürümde yeniden kimlik doğrulama/onay alın. Kalıcı güvenlik geçmişini geçici giriş kayıtlarıyla birlikte temizlemeyin.

`STATE_INTEGRITY` aynı zamanda bozulma veya yanlış anahtar belirtir. Bu hatada eski format fallback'i açmayın. Yedek/anahtar/anchor doğrulamasını tamamlamadan hizmeti yeniden açmayın. Tam eski bir snapshot'ın geri alınmasını algılamak için bağımsız güncel anchor gereklidir.
