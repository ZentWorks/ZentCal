package db

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
  version integer PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);`,
	`CREATE TABLE IF NOT EXISTS settings (
  key text PRIMARY KEY,
  value text NOT NULL DEFAULT '',
  secret boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);`,
	`CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL DEFAULT 'user' CHECK (role IN ('owner','administrator','user')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','invited','disabled','locked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login timestamptz,
  last_sync timestamptz
);`,
	`CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uidx ON users(lower(email));`,
	`CREATE TABLE IF NOT EXISTS login_attempts (
  identity text PRIMARY KEY,
  failures integer NOT NULL DEFAULT 0,
  last_failed_at timestamptz NOT NULL DEFAULT now(),
  blocked_until timestamptz
);`,
	`CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  csrf_token text NOT NULL,
  ip inet,
  user_agent text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now()
);`,
	`CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
 CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);`,
	`CREATE TABLE IF NOT EXISTS calendars (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  color text NOT NULL DEFAULT '#4f8cff',
  type text NOT NULL DEFAULT 'calendar' CHECK (type IN ('calendar','resource')),
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);`,
	`CREATE TABLE IF NOT EXISTS memberships (
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner','editor','contributor','viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(calendar_id,user_id)
);`,
	`CREATE INDEX IF NOT EXISTS memberships_user_idx ON memberships(user_id);`,
	`CREATE TABLE IF NOT EXISTS events (
  id uuid PRIMARY KEY,
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  uid text NOT NULL,
  href text NOT NULL,
  summary text NOT NULL DEFAULT '',
  dtstart timestamptz,
  dtend timestamptz,
  ics text NOT NULL,
  etag text NOT NULL,
  version integer NOT NULL DEFAULT 1,
  created_by uuid REFERENCES users(id),
  updated_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(calendar_id, uid),
  UNIQUE(calendar_id, href)
);`,
	`CREATE INDEX IF NOT EXISTS events_calendar_idx ON events(calendar_id);
 CREATE INDEX IF NOT EXISTS events_range_idx ON events(dtstart,dtend);
 CREATE INDEX IF NOT EXISTS events_uid_idx ON events(uid);`,
	`CREATE TABLE IF NOT EXISTS event_tombstones (
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  href text NOT NULL,
  deleted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(calendar_id,href,deleted_at)
);`,
	`CREATE INDEX IF NOT EXISTS event_tombstones_deleted_idx ON event_tombstones(calendar_id,deleted_at);`,
	`CREATE TABLE IF NOT EXISTS event_versions (
  id uuid PRIMARY KEY,
  event_id uuid NOT NULL,
  version integer NOT NULL,
  action text NOT NULL,
  ics text NOT NULL,
  actor_user_id uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(event_id,version)
);`,
	`CREATE TABLE IF NOT EXISTS audit_logs (
  id bigserial PRIMARY KEY,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text NOT NULL DEFAULT '',
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip inet,
  user_agent text NOT NULL DEFAULT '',
  request_id text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);`,
	`CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at DESC);
 CREATE INDEX IF NOT EXISTS audit_actor_idx ON audit_logs(actor_user_id);
 CREATE INDEX IF NOT EXISTS audit_resource_idx ON audit_logs(resource_type,resource_id);`,
	`CREATE TABLE IF NOT EXISTS api_tokens (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  prefix text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  scopes text[] NOT NULL DEFAULT '{}',
  expires_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);`,
	`CREATE TABLE IF NOT EXISTS invitations (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  name text NOT NULL DEFAULT '',
  token_hash text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'user',
  invited_by uuid REFERENCES users(id),
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);`,
	`CREATE TABLE IF NOT EXISTS app_passwords (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  prefix text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_type text NOT NULL DEFAULT 'local' CHECK (auth_type IN ('local','oidc'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject text;
CREATE UNIQUE INDEX IF NOT EXISTS users_oidc_identity_uidx ON users(oidc_issuer,oidc_subject) WHERE oidc_subject IS NOT NULL;`,
	`CREATE TABLE IF NOT EXISTS oidc_states (
  state_hash text PRIMARY KEY,
  nonce text NOT NULL,
  verifier text NOT NULL,
  redirect_uri text NOT NULL,
  return_to text NOT NULL DEFAULT '/',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oidc_states_expiry_idx ON oidc_states(expires_at);`,
	`CREATE TABLE IF NOT EXISTS webhooks (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  target_url text NOT NULL,
  secret text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  allow_private boolean NOT NULL DEFAULT false,
  events text[] NOT NULL DEFAULT '{}',
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id uuid PRIMARY KEY,
  webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event text NOT NULL,
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','success','failed')),
  attempt integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  http_status integer,
  response_ms bigint,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_queue_idx ON webhook_deliveries(status,next_attempt_at);
CREATE INDEX IF NOT EXISTS webhook_deliveries_created_idx ON webhook_deliveries(created_at DESC);`,
	`ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS auth_type text NOT NULL DEFAULT 'hmac' CHECK (auth_type IN ('bearer','hmac','none'));`,
	`ALTER TABLE app_passwords ADD COLUMN IF NOT EXISTS dav_digest_ha1 text;`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS language text NOT NULL DEFAULT 'de';
ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT 'Europe/Berlin';
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS users_auth_type_idx ON users(auth_type);`,
	`CREATE TABLE IF NOT EXISTS backups (
  id uuid PRIMARY KEY,
  filename text NOT NULL,
  provider text NOT NULL CHECK (provider IN ('local','sftp','s3')),
  object_key text NOT NULL,
  status text NOT NULL DEFAULT 'running' CHECK (status IN ('running','success','failed')),
  size_bytes bigint NOT NULL DEFAULT 0,
  checksum text NOT NULL DEFAULT '',
  error text NOT NULL DEFAULT '',
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS backups_created_idx ON backups(created_at DESC);`,
	`ALTER TABLE users ALTER COLUMN language SET DEFAULT 'auto';`,
	`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reauthenticated_at timestamptz;
CREATE TABLE IF NOT EXISTS password_reset_requests (
  identity text PRIMARY KEY,
  last_requested_at timestamptz NOT NULL DEFAULT now()
);`,
	`CREATE TABLE IF NOT EXISTS event_attendees (
  id uuid PRIMARY KEY,
  event_id uuid NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  email text NOT NULL,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  cn text NOT NULL DEFAULT '',
  partstat text NOT NULL DEFAULT 'NEEDS-ACTION' CHECK (partstat IN ('NEEDS-ACTION','ACCEPTED','DECLINED','TENTATIVE')),
  rsvp boolean NOT NULL DEFAULT true,
  response_token_hash text,
  response_token_secret text,
  response_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS event_attendees_event_email_uidx ON event_attendees(event_id, lower(email));
CREATE INDEX IF NOT EXISTS event_attendees_user_idx ON event_attendees(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS event_attendees_response_token_uidx ON event_attendees(response_token_hash) WHERE response_token_hash IS NOT NULL;
CREATE TABLE IF NOT EXISTS scheduling_messages (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_id uuid REFERENCES events(id) ON DELETE SET NULL,
  direction text NOT NULL CHECK (direction IN ('inbox','outbox')),
  method text NOT NULL,
  href text NOT NULL,
  ics text NOT NULL,
  schedule_tag text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS scheduling_messages_user_href_uidx ON scheduling_messages(user_id,direction,href);
CREATE INDEX IF NOT EXISTS scheduling_messages_user_created_idx ON scheduling_messages(user_id,direction,created_at DESC);
CREATE TABLE IF NOT EXISTS scheduling_deliveries (
  id uuid PRIMARY KEY,
  event_id uuid REFERENCES events(id) ON DELETE SET NULL,
  recipient_email text NOT NULL,
  method text NOT NULL,
  ics text NOT NULL,
  base_url text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','success','failed')),
  attempt integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz
);
CREATE INDEX IF NOT EXISTS scheduling_deliveries_queue_idx ON scheduling_deliveries(status,next_attempt_at);
ALTER TABLE events ADD COLUMN IF NOT EXISTS schedule_tag text NOT NULL DEFAULT '';
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS system_kind text NOT NULL DEFAULT '';
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS system_owner_user_id uuid REFERENCES users(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS calendars_system_owner_kind_uidx ON calendars(system_owner_user_id,system_kind) WHERE system_kind<>'';
ALTER TABLE event_attendees ADD COLUMN IF NOT EXISTS attendee_event_id uuid REFERENCES events(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS event_attendees_attendee_event_idx ON event_attendees(attendee_event_id);
`,

	`ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name text NOT NULL DEFAULT '';
UPDATE users
SET first_name = CASE WHEN position(' ' in trim(name)) > 0 THEN split_part(trim(name),' ',1) ELSE trim(name) END,
    last_name = CASE WHEN position(' ' in trim(name)) > 0 THEN trim(substr(trim(name), position(' ' in trim(name)) + 1)) ELSE '' END
WHERE first_name='';
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'normal' CHECK (mode IN ('normal','personal'));`,
	`ALTER TABLE calendars ADD COLUMN IF NOT EXISTS dav_name text;
UPDATE calendars SET dav_name=id::text WHERE dav_name IS NULL OR btrim(dav_name)='';
ALTER TABLE calendars ALTER COLUMN dav_name SET NOT NULL;
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS calendar_timezone text NOT NULL DEFAULT '';`,
	`ALTER TABLE users DROP COLUMN IF EXISTS dav_digest_ha1;
ALTER TABLE memberships ADD COLUMN IF NOT EXISTS dav_name text;
UPDATE memberships m SET dav_name=c.dav_name FROM calendars c WHERE c.id=m.calendar_id AND (m.dav_name IS NULL OR btrim(m.dav_name)='');
ALTER TABLE memberships ALTER COLUMN dav_name SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS memberships_user_dav_name_uidx ON memberships(user_id,dav_name);
CREATE INDEX IF NOT EXISTS events_calendar_updated_idx ON events(calendar_id,updated_at);
CREATE INDEX IF NOT EXISTS scheduling_messages_user_direction_idx ON scheduling_messages(user_id,direction,created_at DESC);`,
	`UPDATE memberships SET role='contributor' WHERE role='editor';
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check CHECK (role IN ('owner','contributor','viewer'));`,
	`ALTER TABLE scheduling_deliveries ADD COLUMN IF NOT EXISTS template_kind text NOT NULL DEFAULT '';`,
	`ALTER TABLE oidc_states ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT 'login';
ALTER TABLE oidc_states ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE oidc_states DROP CONSTRAINT IF EXISTS oidc_states_purpose_check;
ALTER TABLE oidc_states ADD CONSTRAINT oidc_states_purpose_check CHECK (purpose IN ('login','link','unlink'));`,
	`ALTER TABLE oidc_states DROP CONSTRAINT IF EXISTS oidc_states_purpose_check;
ALTER TABLE oidc_states ADD CONSTRAINT oidc_states_purpose_check CHECK (purpose IN ('login','direct','existing','reauth','link','unlink'));`,
	`CREATE TABLE IF NOT EXISTS admin_api_tokens (
  id uuid PRIMARY KEY,
  created_by uuid REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  prefix text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  scopes text[] NOT NULL DEFAULT '{}',
  expires_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS admin_api_tokens_creator_idx ON admin_api_tokens(created_by,created_at DESC);
DELETE FROM settings WHERE key='instance_name';`,
	// Compatibility slot: an intermediate 0.1.23 build inserted the calendar-create
	// permission before the already-released admin API migration. Some databases
	// therefore already have this version recorded. Never reuse it for schema work.
	`SELECT 1;`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS can_create_calendars boolean NOT NULL DEFAULT true;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS can_create_calendars boolean NOT NULL DEFAULT true;`,
	`CREATE TABLE IF NOT EXISTS password_reset_jobs (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash text NOT NULL DEFAULT '',
  temporary_password_secret text NOT NULL DEFAULT '',
  base_url text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','success','failed')),
  attempt integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);
CREATE INDEX IF NOT EXISTS password_reset_jobs_queue_idx ON password_reset_jobs(status,next_attempt_at);
CREATE UNIQUE INDEX IF NOT EXISTS password_reset_jobs_active_user_uidx ON password_reset_jobs(user_id) WHERE status IN ('pending','sending');`,
	`ALTER TABLE backups ADD COLUMN IF NOT EXISTS stage text NOT NULL DEFAULT '';`,
	`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reauth_purpose text NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reauth_target text NOT NULL DEFAULT '';`,
	`CREATE TABLE IF NOT EXISTS email_deliveries (
  id uuid PRIMARY KEY,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  mail_type text NOT NULL,
  recipient_masked text NOT NULL,
  status text NOT NULL CHECK (status IN ('success','failed')),
  attempt integer NOT NULL DEFAULT 1,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);
CREATE INDEX IF NOT EXISTS email_deliveries_created_idx ON email_deliveries(created_at DESC);
CREATE INDEX IF NOT EXISTS email_deliveries_status_idx ON email_deliveries(status,created_at DESC);`,
	`ALTER TABLE scheduling_deliveries ADD COLUMN IF NOT EXISTS change_keys text NOT NULL DEFAULT '';`,
	`DELETE FROM event_versions WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.deleted_at IS NOT NULL AND coalesce(c.system_kind,'')='')
 OR event_id IN (SELECT ea.attendee_event_id FROM event_attendees ea JOIN events e ON e.id=ea.event_id JOIN calendars c ON c.id=e.calendar_id WHERE c.deleted_at IS NOT NULL AND coalesce(c.system_kind,'')='' AND ea.attendee_event_id IS NOT NULL);
DELETE FROM scheduling_deliveries WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.deleted_at IS NOT NULL AND coalesce(c.system_kind,'')='');
DELETE FROM scheduling_messages WHERE event_id IN (SELECT e.id FROM events e JOIN calendars c ON c.id=e.calendar_id WHERE c.deleted_at IS NOT NULL AND coalesce(c.system_kind,'')='');
DELETE FROM events WHERE id IN (SELECT ea.attendee_event_id FROM event_attendees ea JOIN events e ON e.id=ea.event_id JOIN calendars c ON c.id=e.calendar_id WHERE c.deleted_at IS NOT NULL AND coalesce(c.system_kind,'')='' AND ea.attendee_event_id IS NOT NULL);
DELETE FROM calendars WHERE deleted_at IS NOT NULL AND coalesce(system_kind,'')='';`,
	`CREATE INDEX IF NOT EXISTS scheduling_deliveries_created_idx ON scheduling_deliveries(created_at);
CREATE INDEX IF NOT EXISTS scheduling_deliveries_event_recipient_idx ON scheduling_deliveries(event_id, lower(recipient_email));
CREATE INDEX IF NOT EXISTS scheduling_messages_processed_idx ON scheduling_messages(processed_at) WHERE processed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS scheduling_messages_event_idx ON scheduling_messages(event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS event_versions_created_idx ON event_versions(created_at);
CREATE INDEX IF NOT EXISTS login_attempts_last_failed_idx ON login_attempts(last_failed_at);
CREATE INDEX IF NOT EXISTS password_reset_requests_last_requested_idx ON password_reset_requests(last_requested_at);`,
	`DELETE FROM settings WHERE key='base_url';`,
	`ALTER TABLE calendars ADD COLUMN IF NOT EXISTS admin_managed boolean NOT NULL DEFAULT false;
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS admin_manager_user_id uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS admin_manager_visible boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS calendars_admin_manager_idx ON calendars(admin_manager_user_id) WHERE admin_managed AND deleted_at IS NULL;`,
}
