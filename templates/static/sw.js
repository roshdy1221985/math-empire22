// ════════════════════════════════════════════════════════════
// 📡 Service Worker — إمبراطورية الرياضيات v4
// PWA + Push Notifications + Smart Caching
// ════════════════════════════════════════════════════════════

const CACHE_VERSION = 'royal-math-v4';
const CACHE_NAME = `royal-math-cache-${CACHE_VERSION}`;

// ملفات أساسية فقط (نتجاهل الأخطاء)
const ESSENTIAL_ASSETS = [
    '/manifest.json',
    '/static/logo.jpg'
];

// ════════════════════════════════════════════════════════════
// 1️⃣ التثبيت
// ════════════════════════════════════════════════════════════
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                // نُضيف ملف بملف لتجنب فشل الكل
                return Promise.allSettled(
                    ESSENTIAL_ASSETS.map(url => cache.add(url).catch(() => {}))
                );
            })
            .then(() => self.skipWaiting())
    );
});

// ════════════════════════════════════════════════════════════
// 2️⃣ التفعيل
// ════════════════════════════════════════════════════════════
self.addEventListener('activate', (event) => {
    event.waitUntil(
        Promise.all([
            caches.keys().then((keys) =>
                Promise.all(
                    keys.filter(k => k.startsWith('royal-math-') && k !== CACHE_NAME)
                        .map(k => caches.delete(k))
                )
            ),
            self.clients.claim()
        ])
    );
});

// ════════════════════════════════════════════════════════════
// 3️⃣ Fetch — Network First (لتحديثات سريعة)
// ════════════════════════════════════════════════════════════
self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET') return;
    
    const url = new URL(event.request.url);
    // تجاهل API و Supabase
    if (url.pathname.startsWith('/api/') || url.hostname.includes('supabase')) return;
    
    event.respondWith(
        fetch(event.request)
            .then((response) => {
                // خزّن النسخة الحديثة
                if (response.ok && url.origin === self.location.origin) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(c => 
                        c.put(event.request, clone).catch(() => {})
                    );
                }
                return response;
            })
            .catch(() => {
                // fallback من cache
                return caches.match(event.request).then((cached) => {
                    if (cached) return cached;
                    if (event.request.mode === 'navigate') {
                        return caches.match('/');
                    }
                });
            })
    );
});

// ════════════════════════════════════════════════════════════
// 4️⃣ Push Notifications
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
        icon: data.icon || '/static/logo.jpg',
        badge: data.badge || '/static/logo.jpg',
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
// 5️⃣ Notification Click
// ════════════════════════════════════════════════════════════
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    if (event.action === 'close') return;
    
    const targetUrl = (event.notification.data && event.notification.data.url) || '/student';
    
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clients) => {
                for (const client of clients) {
                    if (client.url.includes('/student') && 'focus' in client) {
                        return client.focus();
                    }
                }
                if (self.clients.openWindow) {
                    return self.clients.openWindow(targetUrl);
                }
            })
    );
});

// ════════════════════════════════════════════════════════════
// 6️⃣ Push Subscription Refresh
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
            }).catch(() => {})
    );
});

// ════════════════════════════════════════════════════════════
// 7️⃣ Message handler (للتحديث)
// ════════════════════════════════════════════════════════════
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});