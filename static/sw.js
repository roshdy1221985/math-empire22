// 📡 Service Worker — إمبراطورية الرياضيات
// يجمع: Offline Caching + Push Notifications

const cacheName = 'royal-math-v3'; // تحديث الإصدار لتفعيل النسخة الجديدة
const staticAssets = [
  '/',
  '/student',
  '/parent',
  '/manifest.json',
  '/static/staticcss/style.css',
  '/static/staticjs/script.js',
  '/static/teacher.jpg'
];

// ════════════════════════════════════════════════════════════
// 1️⃣ التثبيت: تخزين الملفات الأساسية للعمل بدون إنترنت
// ════════════════════════════════════════════════════════════
self.addEventListener('install', async (e) => {
    const cache = await caches.open(cacheName);
    // نتجاهل الأخطاء لكل ملف بشكل منفصل (لو ملف غير موجود، لا يفشل التثبيت)
    await Promise.all(
        staticAssets.map(url =>
            cache.add(url).catch(err => console.warn('[sw] فشل تخزين:', url, err))
        )
    );
    return self.skipWaiting();
});

// ════════════════════════════════════════════════════════════
// 2️⃣ التفعيل: تنظيف الكاش القديم
// ════════════════════════════════════════════════════════════
self.addEventListener('activate', (e) => {
    e.waitUntil(
        Promise.all([
            caches.keys().then(keys =>
                Promise.all(keys.map(key => {
                    if (key !== cacheName) return caches.delete(key);
                }))
            ),
            self.clients.claim()
        ])
    );
});

// ════════════════════════════════════════════════════════════
// 3️⃣ استراتيجية fetch: Network-first مع fallback للكاش
// ════════════════════════════════════════════════════════════
self.addEventListener('fetch', (e) => {
    // تخطّى طلبات API و POST (لا نخزّنها)
    if (e.request.method !== 'GET') return;
    if (e.request.url.includes('/api/')) return;
    
    e.respondWith(
        fetch(e.request).catch(() => caches.match(e.request))
    );
});

// ════════════════════════════════════════════════════════════
// 4️⃣ 📬 استقبال Push Notifications من الخادم
// تظهر الإشعارات على شاشة الجهاز حتى لو كان التطبيق مغلقاً
// ════════════════════════════════════════════════════════════
self.addEventListener('push', (event) => {
    let data = {};
    try {
        data = event.data ? event.data.json() : {};
    } catch (err) {
        data = {
            title: '📚 إمبراطورية الرياضيات',
            body: event.data ? event.data.text() : 'لديك إشعار جديد!'
        };
    }

    const title = data.title || '📚 إمبراطورية الرياضيات';
    const options = {
        body: data.body || 'لديك تحديث جديد!',
        icon: data.icon || '/static/teacher.jpg',
        badge: data.badge || '/static/teacher.jpg',
        image: data.image,
        tag: data.tag || 'math-empire-notif',
        requireInteraction: data.requireInteraction || false,
        vibrate: [200, 100, 200, 100, 200],
        dir: 'rtl',
        lang: 'ar',
        data: {
            url: data.url || '/student',
            type: data.type || 'general',
            timestamp: Date.now()
        },
        actions: data.actions || [
            { action: 'open', title: '🚀 افتح المنصة' },
            { action: 'close', title: '✕ إغلاق' }
        ]
    };

    event.waitUntil(
        self.registration.showNotification(title, options)
    );
});

// ════════════════════════════════════════════════════════════
// 5️⃣ 🖱️ معالجة النقر على الإشعار
// ════════════════════════════════════════════════════════════
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    if (event.action === 'close') return;
    
    const targetUrl = event.notification.data?.url || '/student';
    
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clients) => {
                // إن كانت نافذة مفتوحة، ركّز عليها
                for (const client of clients) {
                    if (client.url.includes('/student') && 'focus' in client) {
                        return client.focus();
                    }
                }
                // وإلا افتح نافذة جديدة
                if (self.clients.openWindow) {
                    return self.clients.openWindow(targetUrl);
                }
            })
    );
});

// ════════════════════════════════════════════════════════════
// 6️⃣ 🔄 تحديث الاشتراك تلقائياً إن انتهى
// ════════════════════════════════════════════════════════════
self.addEventListener('pushsubscriptionchange', (event) => {
    event.waitUntil(
        self.registration.pushManager.subscribe(event.oldSubscription.options)
            .then((newSub) => {
                return fetch('/api/push/refresh', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ subscription: newSub })
                });
            })
    );
});
