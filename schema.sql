create table if not exists simple_auth_users (
  username text primary key,
  password_hash text,
  created_at timestamptz not null default now()
);
