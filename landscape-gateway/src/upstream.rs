use std::io;
use std::time::Duration;

use futures_util::future::select_ok;
use tokio::net::{TcpStream, lookup_host};
use tokio::time::{Instant, timeout};

/// DNS and all connection attempts share the caller's timeout.
pub(crate) async fn connect_tcp(host: &str, port: u16, budget: Duration) -> io::Result<TcpStream> {
    let start = Instant::now();
    timeout(budget, async {
        let addresses = lookup_host((host, port)).await?;
        let remaining = budget.saturating_sub(start.elapsed());
        let head_start = Duration::from_millis(250).min(remaining / 2);
        first_connected(addresses.map(TcpStream::connect), head_start).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connection timed out"))?
}

async fn first_connected<T>(
    mut candidates: impl Iterator<Item = impl Future<Output = io::Result<T>>>,
    head_start: Duration,
) -> io::Result<T> {
    let first = candidates.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "upstream has no addresses")
    })?;
    let mut fallbacks = candidates.peekable();
    if fallbacks.peek().is_none() {
        return first.await;
    }

    let mut first = Box::pin(first);
    let mut attempts = Vec::new();
    match timeout(head_start, &mut first).await {
        Ok(Ok(stream)) => return Ok(stream),
        Ok(Err(_)) => {}
        // Keep the preferred connection in the race after its head start.
        Err(_) => attempts.push(first),
    }
    attempts.extend(fallbacks.map(Box::pin));
    select_ok(attempts).await.map(|(stream, _remaining)| stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    #[tokio::test]
    async fn a_stalled_address_does_not_hide_a_reachable_fallback() {
        let attempts = [0, 1, 2].into_iter().map(|index| async move {
            match index {
                0 => pending().await,
                1 => Err(io::ErrorKind::ConnectionRefused.into()),
                _ => Ok(index),
            }
        });
        let result = timeout(Duration::from_secs(1), first_connected(attempts, Duration::ZERO))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, 2);
    }

    #[tokio::test]
    async fn reachable_preferred_address_needs_no_fallback_connections() {
        let attempts = [false, true].into_iter().map(|fallback| async move {
            assert!(!fallback, "started a fallback for a healthy preferred address");
            Ok(())
        });
        first_connected(attempts, Duration::from_millis(250)).await.unwrap();
    }

    #[tokio::test]
    async fn preferred_connection_can_finish_after_the_fallback_starts() {
        let fallback_started = tokio::sync::Notify::new();
        let attempts = [true, false].into_iter().map(async |preferred| {
            if preferred {
                fallback_started.notified().await;
                Ok(())
            } else {
                fallback_started.notify_one();
                pending().await
            }
        });
        timeout(Duration::from_secs(1), first_connected(attempts, Duration::ZERO))
            .await
            .unwrap()
            .unwrap();
    }
}
