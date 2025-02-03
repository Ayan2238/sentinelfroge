use kubernetes_openapi::api::apps::v1::Deployment;
use serde_yaml;

pub struct ClusterManager;

impl ClusterManager {
    pub fn create_deployment(config: &str) -> Deployment {
        serde_yaml::from_str(config).unwrap()
    }

    pub fn auto_scale(replicas: i32) -> String {
        format!(r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel-nodes
spec:
  replicas: {}
  template:
    spec:
      containers:
      - name: scanner
        image: sentinelforge:latest
        resources:
          limits:
            cpu: "1000m"
            memory: "2Gi"
"#, replicas)
    }
}