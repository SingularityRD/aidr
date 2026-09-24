-- Pack bytes are delivered only through the authenticated packs-download proxy.
-- Keep the backing bucket private; only the service role may publish objects or
-- mint the short-lived upstream URL consumed by the proxy.
insert into storage.buckets (id, name, public)
values ('aidr-packs', 'aidr-packs', false)
on conflict (id) do update set public = false;
