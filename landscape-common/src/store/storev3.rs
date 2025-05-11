use crate::dns::{CloudFlareMode, DNSResolveMode, DNSRuleConfig, DnsUpstreamType, DomainMatchType, RuleSource};
use crate::store::store_trait::LandScapeBaseStore;
use crate::store::storev2::{LandScapeStore, StoreFileManager};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug)]
pub struct PostgresStoreManager<T> {
    pool: PgPool,
    table_name: String,
    _marker: std::marker::PhantomData<T>,
}
#[async_trait]
impl LandScapeBaseStore<DNSRuleConfig> for PostgresStoreManager<DNSRuleConfig> {
    async fn set(&mut self, data: DNSRuleConfig) {
        let mut tx = self.pool.begin().await.unwrap();

        // First, upsert the main rule config
        sqlx::query(
            r#"
            INSERT INTO dns_rule_configs (name, index, enable, filter, resolve_mode_type, mark_type, mark_flow_id, flow_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (index) DO UPDATE SET
                name = EXCLUDED.name,
                enable = EXCLUDED.enable,
                filter = EXCLUDED.filter,
                resolve_mode_type = EXCLUDED.resolve_mode_type,
                mark_type = EXCLUDED.mark_type,
                mark_flow_id = EXCLUDED.mark_flow_id,
                flow_id = EXCLUDED.flow_id,
                updated_at = NOW()
            "#,
        )
            .bind(data.name)
            .bind(data.index as i32)
            .bind(data.enable)
            .bind(data.filter.to_string())
            .bind(data.resolve_mode.to_type_string())
            .bind(data.mark.to_type_string())
            .bind(data.mark.to_flow_id())
            .bind(data.flow_id as i32)
            .execute(&mut *tx)
            .await.unwrap();

        // Handle the different resolve modes
        match data.resolve_mode {
            DNSResolveMode::Redirect { ips } => {
                self.handle_redirect_mode(&mut tx, data.index, ips).await.unwrap();
            }
            DNSResolveMode::Upstream { upstream, ips, port } => {
                self.handle_upstream_mode(&mut tx, data.index, upstream, ips, port).await.unwrap();
            }
            DNSResolveMode::CloudFlare { mode } => {
                self.handle_cloudflare_mode(&mut tx, data.index, mode).await.unwrap();
            }
        }

        // Handle rule sources
        self.handle_rule_sources(&mut tx, data.index, data.source).await.unwrap();

        tx.commit().await.unwrap();
    }

    async fn get(&mut self, key: &str) -> Option<DNSRuleConfig> {
        todo!()
    }

    async  fn list(&mut self) -> Vec<DNSRuleConfig> {
        todo!()
    }

    async fn del(&mut self, key: &str) {
        todo!()
    }

    async fn truncate(&mut self) {
        todo!()
    }
}
use sqlx::Error as SqlxError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsRuleConfigError {
    #[error("Database error: {0}")]
    Database(#[from] SqlxError),

    #[error("Invalid IP address")]
    InvalidIpAddress,

    #[error("Invalid domain match type")]
    InvalidDomainMatchType,

    #[error("Invalid upstream type")]
    InvalidUpstreamType,

    #[error("Invalid cloudflare mode")]
    InvalidCloudflareMode,

    #[error("Invalid filter type")]
    InvalidFilterType,

    #[error("Invalid mark type")]
    InvalidMarkType,
}

impl<T> PostgresStoreManager<T>
where
    T: LandScapeStore + Serialize + for<'de> Deserialize<'de>,
{
    /// Create a new PostgreSQL-based store manager
    pub async fn new(db_url: &str, table_name: String) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new().max_connections(5).connect(db_url).await?;

        Ok(Self {
            pool,
            table_name,
            _marker: std::marker::PhantomData,
        })
    }

    pub async fn handle_redirect_mode(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        rule_index: u32,
        ips: Vec<IpAddr>,
    ) -> Result<(), DnsRuleConfigError> {
        sqlx::query(
            r#"
            DELETE FROM dns_rule_redirect_ips
            WHERE rule_id = (SELECT id FROM dns_rule_configs WHERE index = $1)
            "#,
        )
            .bind(rule_index as i32)
            .execute(&mut **tx)
            .await?;
        for (order, ip) in ips.into_iter().enumerate() {
            sqlx::query(
                r#"
                INSERT INTO dns_rule_redirect_ips (rule_id, ip_address, ip_order)
                SELECT id, $2, $3
                FROM dns_rule_configs
                WHERE index = $1
                "#,
            )
                .bind(rule_index as i32)
                .bind(ip.to_string())
                .bind(order as i32)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
    async fn handle_upstream_mode(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        rule_index: u32,
        upstream: DnsUpstreamType,
        ips: Vec<IpAddr>,
        port: Option<u16>,
    ) -> Result<(), DnsRuleConfigError> {
        // Delete existing upstream and its IPs
        sqlx::query(
            r#"
            DELETE FROM dns_rule_upstream_ips
            WHERE upstream_id IN (
                SELECT id FROM dns_rule_upstreams
                WHERE rule_id = (SELECT id FROM dns_rule_configs WHERE index = $1)
            )
            "#,
        )
            .bind(rule_index as i32)
            .execute(&mut **tx)
            .await?;

        sqlx::query(
            r#"
            DELETE FROM dns_rule_upstreams
            WHERE rule_id = (SELECT id FROM dns_rule_configs WHERE index = $1)
            "#,
        )
            .bind(rule_index as i32)
            .execute(&mut **tx)
            .await?;

        // Insert new upstream
        let (upstream_type, domain) = match upstream {
            DnsUpstreamType::Plaintext => ("plaintext", None),
            DnsUpstreamType::Tls { domain } => ("tls", Some(domain)),
            DnsUpstreamType::Https { domain } => ("https", Some(domain)),
        };

        let upstream_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO dns_rule_upstreams (rule_id, upstream_type, domain, port)
            SELECT id, $2, $3, $4
            FROM dns_rule_configs
            WHERE index = $1
            RETURNING id
            "#,
        )
            .bind(rule_index as i32)
            .bind(upstream_type)
            .bind(domain)
            .bind(port.map(|p| p as i16))
            .fetch_one(&mut **tx)
            .await?;

        // Insert upstream IPs
        for (order, ip) in ips.into_iter().enumerate() {
            sqlx::query(
                r#"
                INSERT INTO dns_rule_upstream_ips (upstream_id, ip_address, ip_order)
                VALUES ($1, $2, $3)
                "#,
            )
                .bind(upstream_id)
                .bind(ip.to_string())
                .bind(order as i32)
                .execute(&mut **tx)
                .await?;
        }

        Ok(())
    }

    async fn handle_cloudflare_mode(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        rule_index: u32,
        mode: CloudFlareMode,
    ) -> Result<(), DnsRuleConfigError> {
        // Delete existing cloudflare mode
        sqlx::query(
            r#"
            DELETE FROM dns_rule_cloudflare_modes
            WHERE rule_id = (SELECT id FROM dns_rule_configs WHERE index = $1)
            "#,
        )
            .bind(rule_index as i32)
            .execute(&mut **tx)
            .await?;

        // Insert new cloudflare mode
        let mode_str = match mode {
            CloudFlareMode::Plaintext => "plaintext",
            CloudFlareMode::Tls => "tls",
            CloudFlareMode::Https => "https",
        };

        sqlx::query(
            r#"
            INSERT INTO dns_rule_cloudflare_modes (rule_id, mode)
            SELECT id, $2
            FROM dns_rule_configs
            WHERE index = $1
            "#,
        )
            .bind(rule_index as i32)
            .bind(mode_str)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    async fn handle_rule_sources(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        rule_index: u32,
        sources: Vec<RuleSource>,
    ) -> Result<(), DnsRuleConfigError> {
        // Delete existing sources
        sqlx::query(
            r#"
            DELETE FROM dns_rule_sources
            WHERE rule_id = (SELECT id FROM dns_rule_configs WHERE index = $1)
            "#,
        )
            .bind(rule_index as i32)
            .execute(&mut **tx)
            .await?;

        // Insert new sources
        for source in sources {
            match source {
                RuleSource::GeoKey { key } => {
                    sqlx::query(
                        r#"
                        INSERT INTO dns_rule_sources (rule_id, source_type, geo_key)
                        SELECT id, 'geo_key', $2
                        FROM dns_rule_configs
                        WHERE index = $1
                        "#,
                    )
                        .bind(rule_index as i32)
                        .bind(key)
                        .execute(&mut **tx)
                        .await?;
                }
                RuleSource::Config(config) => {
                    let match_type = match config.match_type {
                        DomainMatchType::Plain => "plain",
                        DomainMatchType::Regex => "regex",
                        DomainMatchType::Domain => "domain",
                        DomainMatchType::Full => "full",
                    };

                    sqlx::query(
                        r#"
                        INSERT INTO dns_rule_sources (rule_id, source_type, domain_match_type, domain_value)
                        SELECT id, 'config', $2, $3
                        FROM dns_rule_configs
                        WHERE index = $1
                        "#,
                    )
                        .bind(rule_index as i32)
                        .bind(match_type)
                        .bind(config.value)
                        .execute(&mut **tx)
                        .await?;
                }
            }
        }

        Ok(())
    }
}
