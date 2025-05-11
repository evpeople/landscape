use async_trait::async_trait;

#[async_trait]
pub trait LandScapeBaseStore<T>: Send {
    async fn set(&mut self, data: T);

    async fn get(&mut self, key: &str) -> Option<T>;

    async fn list(&mut self) -> Vec<T>;

    async fn del(&mut self, key: &str);

    async fn truncate(&mut self);
}
