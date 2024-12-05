use std::time::{Duration, Instant};
use tokio::time::sleep;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct RateLimiter {
    last_request: Arc<Mutex<Instant>>,
    min_delay: Duration,
    max_retries: u32,
}

impl RateLimiter {
    pub fn new(min_delay_ms: u64, max_retries: u32) -> Self {
        Self {
            last_request: Arc::new(Mutex::new(Instant::now())),
            min_delay: Duration::from_millis(min_delay_ms),
            max_retries,
        }
    }

    pub async fn execute<F, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: Fn() -> Result<T, E> + Send,
        E: std::fmt::Debug,
    {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.max_retries {
            {
                let mut last = self.last_request.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(*last);

                if elapsed < self.min_delay {
                    let wait_time = self.min_delay - elapsed;
                    sleep(wait_time).await;
                }

                *last = Instant::now();
            }

            match operation() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    attempts += 1;
                    if attempts < self.max_retries {
                        // Exponential backoff
                        sleep(Duration::from_millis(100 * 2u64.pow(attempts))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(100, 3);
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = limiter
            .execute(move || {
                let current = counter_clone.fetch_add(1, Ordering::SeqCst);
                if current < 2 {
                    Err("Simulated failure")
                } else {
                    Ok("Success")
                }
            })
            .await;

        assert_eq!(result, Ok("Success"));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
