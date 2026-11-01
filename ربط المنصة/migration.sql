-- 📚 المراجعات التفاعلية — جدولان جديدان فقط (لا تمس أي جدول موجود)
create table if not exists review_events (
  id bigserial primary key,
  type text not null, ts bigint not null,
  app text, unit int, title text, device text, student text,
  data jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);
create index if not exists review_events_dev on review_events(device);
create index if not exists review_events_app on review_events(app, unit, ts);

create table if not exists review_licenses (
  device text not null, scope text not null, code text not null,
  customer text, note text, active boolean default true,
  created_at timestamptz default now(),
  primary key (device, scope)
);

-- 🔒 الحماية: لا أحد يقرأ أو يكتب مباشرة بالمفتاح العام (anon)
-- السيرفر يصل إليها بمفتاح الخدمة SUPABASE_SERVICE_KEY الذي يتجاوز RLS
alter table review_events enable row level security;
alter table review_licenses enable row level security;
