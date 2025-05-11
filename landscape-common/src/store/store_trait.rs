pub trait LandScapeBaseStore<T>:Send {
    fn set(&mut self, data: T);

    fn get(&mut self, key: &str) -> Option<T>;

    fn list(&mut self) -> Vec<T>;

    fn del(&mut self, key: &str);

    fn truncate(&mut self);
}