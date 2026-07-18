-- Creates isolated app user with minimal privileges.
-- Runs once on first PostgreSQL container startup via /docker-entrypoint-initdb.d/.
-- HELMLY_APP_PASS is substituted by the init wrapper using the mounted secret.

\set app_pass `cat /run/secrets/helmly-dashboard-pg-pass`

CREATE USER helmly_dashboard_app WITH PASSWORD :'app_pass' NOSUPERUSER NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE helmly_dashboard TO helmly_dashboard_app;

\connect helmly_dashboard

GRANT USAGE, CREATE ON SCHEMA public TO helmly_dashboard_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO helmly_dashboard_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO helmly_dashboard_app;
