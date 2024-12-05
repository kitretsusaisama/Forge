use governor::{Quota, RateLimiter as Governor};
use nonzero_ext::nonzero;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use super::*;

pub struct RateLimitedUserManager {
    inner: UserManager,
    limiter: Arc<Governor<String, _, _>>,
}

impl RateLimitedUserManager {
    pub fn new() -> Self {
        let quota = Quota::per_second(NonZeroU32::new(5).unwrap());
        let limiter = Arc::new(Governor::keyed(quota));
        
        Self {
            inner: UserManager::new(),
            limiter,
        }
    }

    pub async fn get_user(&self, id: &str) -> Option<User> {
        self.limiter.until_ready(id.to_string()).await;
        self.inner.get_user(id).await
    }

    pub async fn add_user(&self, user: User) -> Result<()> {
        self.limiter.until_ready(user.id.clone()).await;
        self.inner.add_user(user).await
    }

    pub async fn remove_user(&self, id: &str) -> Option<User> {
        self.limiter.until_ready(id.to_string()).await;
        self.inner.remove_user(id).await
    }

    pub async fn list_users(&self) -> Vec<User> {
        self.limiter.until_ready("list".to_string()).await;
        self.inner.list_users().await
    }

    pub async fn update_user(&self, id: &str, user: User) -> Option<User> {
        self.limiter.until_ready(id.to_string()).await;
        self.inner.update_user(id, user).await
    }
}

impl Default for RateLimitedUserManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    #[tokio::test]
    async fn test_rate_limiting() {
        let manager = RateLimitedUserManager::new();
        let start = Instant::now();
        
        for i in 0..10 {
            let user = User {
                id: i.to_string(),
                username: format!("user{}", i),
                display_name: None,
                email: None,
                password_hash: "hash".to_string(),
                permissions: vec![],
                last_login: None,
            };
            manager.add_user(user).await.unwrap();
        }

        // Should take at least 2 seconds due to rate limiting (5 requests per second)
        assert!(start.elapsed() >= Duration::from_secs(2));
    }
}
