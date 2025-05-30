use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use serde::Serialize;
use tokio::sync::{mpsc, RwLock};
use ts_rs::TS;

use crate::event::firewall::{ConnectMetric, FirewallKey, FirewallMessage, FirewallMetric};

const CHANNEL_SIZE: usize = 2048;

#[derive(Debug, Serialize, TS)]
#[ts(export, export_to = "common/metric.d.ts")]
pub struct FrontEndFirewallConnectData {
    key: FirewallKey,
    value: SingleConnectMetric,
}

#[derive(Debug, Default, Serialize, TS)]
#[ts(export, export_to = "common/metric.d.ts")]
pub struct FrontEndFirewallMetricServiceData {
    pub connects: HashSet<FirewallKey>,
    pub connect_metrics: Vec<FrontEndFirewallConnectData>,
}

#[derive(Debug, Serialize, Clone, TS)]
#[ts(export, export_to = "common/metric.d.ts")]
pub struct SingleConnectMetric {
    agg: ConnectMetric,
    #[ts(type = "Array<FirewallMetric>")]
    metrics: VecDeque<FirewallMetric>,
}

#[derive(Debug, Default)]
pub struct FirewallMetricServiceData {
    pub connects: HashSet<FirewallKey>,
    pub connect_metrics: HashMap<FirewallKey, SingleConnectMetric>,
}

#[derive(Clone)]
pub struct FirewallMetricService {
    data: Arc<RwLock<FirewallMetricServiceData>>,
    msg_channel: mpsc::Sender<FirewallMessage>,
}

impl FirewallMetricService {
    pub async fn new() -> Self {
        let data = Arc::new(RwLock::new(FirewallMetricServiceData::default()));
        let data_clone = data.clone();

        let (event_channel_tx, mut event_channel_rx) =
            tokio::sync::mpsc::channel::<FirewallMessage>(CHANNEL_SIZE);
        tokio::spawn(async move {
            while let Some(data) = event_channel_rx.recv().await {
                let mut write = data_clone.write().await;
                match data {
                    FirewallMessage::Event(firewall_event) => {
                        let (key, ev_type) = firewall_event.convert_to_key();
                        match ev_type {
                            crate::event::firewall::FirewallEventType::Unknow => {}
                            crate::event::firewall::FirewallEventType::CreateConnect => {
                                write.connects.insert(key);
                            }
                            crate::event::firewall::FirewallEventType::DisConnct => {
                                write.connects.remove(&key);
                                write.connect_metrics.remove(&key);
                            }
                        }
                    }
                    FirewallMessage::Metric(firewall_metric) => {
                        let (key, metric) = firewall_metric.convert_to_key();
                        // tracing::info!("key metric: {key:?}");
                        match write.connect_metrics.entry(key) {
                            std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                                let connect_info = occupied_entry.get_mut();
                                connect_info.agg.append_other(&metric);
                                connect_info.metrics.push_back(firewall_metric);
                                if connect_info.metrics.len() > 60 {
                                    connect_info.metrics.pop_front();
                                }
                            }
                            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                                vacant_entry.insert(SingleConnectMetric {
                                    agg: metric,
                                    metrics: VecDeque::from(vec![firewall_metric]),
                                });
                            }
                        }
                    }
                }
            }
        });

        FirewallMetricService { data, msg_channel: event_channel_tx }
    }

    pub async fn convert_to_front_formart(&self) -> FrontEndFirewallMetricServiceData {
        let data = self.data.read().await;
        let mut connect_metrics = vec![];
        for (key, value) in data.connect_metrics.iter() {
            connect_metrics
                .push(FrontEndFirewallConnectData { key: key.clone(), value: value.clone() });
        }
        FrontEndFirewallMetricServiceData { connects: data.connects.clone(), connect_metrics }
    }

    pub fn send_firewall_msg(&self, msg: FirewallMessage) {
        if let Err(e) = self.msg_channel.try_send(msg) {
            tracing::error!("send firewall metric error: {e:?}");
        }
    }
}
