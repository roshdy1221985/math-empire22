const cacheName = 'royal-math-v2'; // تحديث الإصدار لتنشيط المتصفح
const staticAssets = [
  '/',
  '/student',
  '/parent',
  '/manifest.json',
  '/static/staticcss/style.css',
  '/static/staticjs/script.js',
  '/static/teacher.jpg'
];

// مرحلة التثبيت: تخزين الملفات الأساسية في ذاكرة الهاتف
self.addEventListener('install', async e => {
  const cache = await caches.open(cacheName);
  await cache.addAll(staticAssets);
  return self.skipWaiting();
});

// تنظيف الكاش القديم عند التحديث
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(keys.map(key => {
        if (key !== cacheName) return caches.delete(key);
      }));
    })
  );
});

// استراتيجية التشغيل: حاول الجلب من الإنترنت، وإذا انقطع، استخدم الذاكرة (Offline)
self.addEventListener('fetch', e => {
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});