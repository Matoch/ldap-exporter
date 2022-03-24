use chrono::prelude::*;
use convert_case::{Case, Casing};
use ldap3::result::Result;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::collections::VecDeque;
use std::env;

pub struct Ldap;

impl Ldap {
    pub async fn go() -> Result<String> {
        match env::var("LDAP_URI") {
            Ok(ldap_uri) => {
                let start_time = Utc::now();
                let (conn, mut ldap) = LdapConnAsync::new(ldap_uri.as_str()).await?;
                ldap3::drive!(conn);
                match env::var("LDAP_BIND_DN") {
                    Ok(bind_dn) => match env::var("LDAP_BIND_PASSWORD") {
                        Ok(bind_pass) => {
                            let _bind_result = ldap
                                .simple_bind(bind_dn.as_str(), bind_pass.as_str())
                                .await?;
                        }
                        _ => (),
                    },
                    _ => {
                        let _bind_result = ldap.sasl_external_bind().await?;
                    }
                }

                let mut all_metrics = String::from("");

                let base_dn = "cn=statistics,cn=monitor";
                let scope = Scope::Subtree;
                let searchphrase = "objectclass=*";
                let attributes = vec!["monitorCounter"];
                let sub_result = search(&mut ldap, base_dn, scope, searchphrase, attributes, false)
                    .await
                    .ok_or(String::from(""));
                if let Ok(metric) = sub_result {
                    all_metrics.push_str(metric.as_str())
                }

                let base_dn = "cn=connections,cn=monitor";
                let scope = Scope::Subtree;
                let searchphrase = "(|(cn=current)(cn=total)(cn=Max File Descriptors))";
                let attributes = vec!["monitorCounter"];
                let sub_result = search(&mut ldap, base_dn, scope, searchphrase, attributes, false)
                    .await
                    .ok_or(String::from(""));
                if let Ok(metric) = sub_result {
                    all_metrics.push_str(metric.as_str())
                }

                // Each Connection
                // Metrics
                // monitorConnectionOpsReceived, monitorConnectionOpsExecuting,
                // monitorConnectionOpsPending, monitorConnectionOpsCompleted,
                // monitorConnectionGet, monitorConnectionRead, monitorConnectionWrite
                // Labels
                // monitorConnectionPeerAddress, monitorConnectionLocalAddress
                // monitorConnectionPeerDomain, monitorConnectionListener,
                // monitorConnectionNumber

                let base_dn = "cn=time,cn=monitor";
                let scope = Scope::Subtree;
                let searchphrase = "(cn=uptime)";
                let attributes = vec!["monitoredInfo"];
                let sub_result = search(&mut ldap, base_dn, scope, searchphrase, attributes, false)
                    .await
                    .ok_or(String::from(""));
                if let Ok(metric) = sub_result {
                    all_metrics.push_str(metric.as_str())
                }

                let base_dn = "cn=waiters,cn=monitor";
                let scope = Scope::Subtree;
                let searchphrase = "objectclass=*";
                let attributes = vec!["monitorCounter"];
                let sub_result = search(&mut ldap, base_dn, scope, searchphrase, attributes, false)
                    .await
                    .ok_or(String::from(""));
                if let Ok(metric) = sub_result {
                    all_metrics.push_str(metric.as_str())
                }

                let base_dn = "cn=threads,cn=monitor";
                let scope = Scope::Subtree;
                let searchphrase = "(|(cn=max)(cn=Max Pending)(cn=Open)(cn=Starting)(cn=Active)(cn=Pending)(cn=Backload))";
                let attributes = vec!["monitoredInfo"];
                let sub_result = search(&mut ldap, base_dn, scope, searchphrase, attributes, false)
                    .await
                    .ok_or(String::from(""));
                if let Ok(metric) = sub_result {
                    all_metrics.push_str(metric.as_str())
                }

                let base_dn = "cn=operations,cn=monitor";
                let scope = Scope::Subtree;
                let searchphrase = "objectclass=*";
                let attributes = vec!["monitorOpInitiated", "monitorOpCompleted"];
                let sub_result = search(&mut ldap, base_dn, scope, searchphrase, attributes, true)
                    .await
                    .ok_or(String::from(""));
                if let Ok(metric) = sub_result {
                    all_metrics.push_str(metric.as_str())
                }

                ldap.unbind().await?;
                let end_time = Utc::now();
                let scrape_time: f64 =
                    end_time.timestamp_millis() as f64 - start_time.timestamp_millis() as f64;
                all_metrics.push_str(
                    format!(
                        "ldap_scrape_duration_seconds {:.5}\n",
                        scrape_time / 1000 as f64
                    )
                    .as_str(),
                );
                return Ok(all_metrics);
            }
            _ => (),
        }
        return Ok(String::from("Nope"));
    }
}

async fn search(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    scope: Scope,
    search: &str,
    attributes: Vec<&str>,
    include_attr: bool,
) -> Option<String> {
    let mut result = String::from("");
    match ldap.search(base_dn, scope, search, attributes).await {
        Ok(search_result) => {
            let rs = search_result.0;
            for entry in rs {
                let parsed_entry: SearchEntry = SearchEntry::construct(entry);
                let metric_name = convert_dn(parsed_entry.dn);
                for (key, mut value) in parsed_entry.attrs {
                    if let Some(metric_value) = value.pop() {
                        if include_attr {
                            result.push_str(
                                format!(
                                    "{}{{stage=\"{}\"}} {}\n",
                                    metric_name,
                                    key.to_case(Case::Snake).split("_").last().unwrap(),
                                    metric_value
                                )
                                .as_str(),
                            );
                        } else {
                            result.push_str(format!("{} {}\n", metric_name, metric_value).as_str());
                        }
                    }
                }
            }
            return Some(result);
        }
        _ => (),
    }
    None
}

pub fn convert_dn(dn: String) -> String {
    let mut split_dn: VecDeque<String> = dn
        .split(",")
        .map(|s| s.replace("cn=", "").replace(" ", "_"))
        .collect();
    let mut metric_prefix = String::from("ldap");
    while let Some(thing) = split_dn.pop_back() {
        metric_prefix.push_str(format!("_{}", thing.to_lowercase()).as_str());
    }
    metric_prefix
}
