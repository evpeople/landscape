-- Add migration script here
CREATE TABLE dns_rule_configs (
                                  id BIGSERIAL PRIMARY KEY,
                                  name TEXT NOT NULL,
                                  index INTEGER NOT NULL,
                                  enable BOOLEAN NOT NULL DEFAULT TRUE,
                                  filter TEXT NOT NULL CHECK (filter IN ('unfilter', 'only_ipv4', 'only_ipv6')),
                                  resolve_mode_type TEXT NOT NULL CHECK (resolve_mode_type IN ('redirect', 'upstream', 'cloudflare')),
                                  mark_type TEXT NOT NULL CHECK (mark_type IN ('keep_going', 'direct', 'drop', 'redirect', 'allow_reuse_port')),
                                  mark_flow_id SMALLINT,
                                  flow_id INTEGER NOT NULL DEFAULT 0,
                                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                                  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_dns_rule_configs_index ON dns_rule_configs(index);

CREATE TABLE dns_rule_redirect_ips (
                                       id BIGSERIAL PRIMARY KEY,
                                       rule_id BIGINT NOT NULL,
                                       ip_address INET NOT NULL,
                                       ip_order INTEGER NOT NULL,
                                       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_rule_redirect_ips_rule_id ON dns_rule_redirect_ips(rule_id);

CREATE TABLE dns_rule_upstreams (
                                    id BIGSERIAL PRIMARY KEY,
                                    rule_id BIGINT NOT NULL,
                                    upstream_type TEXT NOT NULL CHECK (upstream_type IN ('plaintext', 'tls', 'https')),
                                    domain TEXT,
                                    port SMALLINT,
                                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_rule_upstreams_rule_id ON dns_rule_upstreams(rule_id);

CREATE TABLE dns_rule_upstream_ips (
                                       id BIGSERIAL PRIMARY KEY,
                                       upstream_id BIGINT NOT NULL,
                                       ip_address INET NOT NULL,
                                       ip_order INTEGER NOT NULL,
                                       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_rule_upstream_ips_upstream_id ON dns_rule_upstream_ips(upstream_id);

CREATE TABLE dns_rule_cloudflare_modes (
                                           id BIGSERIAL PRIMARY KEY,
                                           rule_id BIGINT NOT NULL,
                                           mode TEXT NOT NULL CHECK (mode IN ('plaintext', 'tls', 'https')),
                                           created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_rule_cloudflare_modes_rule_id ON dns_rule_cloudflare_modes(rule_id);

CREATE TABLE dns_rule_sources (
                                  id BIGSERIAL PRIMARY KEY,
                                  rule_id BIGINT NOT NULL,
                                  source_type TEXT NOT NULL CHECK (source_type IN ('geo_key', 'config')),
                                  geo_key TEXT,
                                  domain_match_type TEXT CHECK (domain_match_type IN ('plain', 'regex', 'domain', 'full')),
                                  domain_value TEXT,
                                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_rule_sources_rule_id ON dns_rule_sources(rule_id);

