//! wss relay link: binary frames `dst_node_id(16) | datagram` out, `src_node_id(16) | datagram` in. Stays attached
//! at all times, so peers can always reach us through the oneqrelay when the direct path is not available.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async_tls_with_config, Connector};

use crate::control::Control;
use crate::engine::Event;
use crate::status::Status;

pub struct RelayCtx {
    pub control: Arc<Mutex<Control>>,
    pub node_id: [u8; 16],
    pub events: mpsc::Sender<Event>,
    pub outgoing: mpsc::Receiver<Vec<u8>>,
    pub connected: Arc<AtomicBool>,
    /// set after the first successful join: the oneqrelay only accepts registered nodes
    pub ready: Arc<Notify>,
    pub status: Arc<Status>,
    pub stop: Arc<Notify>,
}

pub async fn run(mut ctx: RelayCtx) {
    let mut backoff = 1.0f64;
    ctx.ready.notified().await;
    loop {
        // login (if needed) and connect
        let (url, token, tls) = {
            let mut c = ctx.control.lock().await;
            if c.token().is_none() {
                if let Err(e) = c.login().await {
                    tracing::warn!("relay login: {e:#}");
                    c.rotate();
                    drop(c);
                    tokio::select! { _ = tokio::time::sleep(Duration::from_secs_f64(backoff)) => {}, _ = ctx.stop.notified() => return }
                    backoff = (backoff * 2.0).min(15.0);
                    continue;
                }
            }
            (c.relay_ws_url(&ctx.node_id), c.token().unwrap_or_default().to_string(), c.tls())
        };
        let outcome: Result<(), anyhow::Error> = async {
            let mut req = url.as_str().into_client_request()?;
            req.headers_mut().insert("Authorization", format!("Bearer {token}").parse()?);
            let (ws, _) = connect_async_tls_with_config(req, None, false, Some(Connector::Rustls(tls))).await?;
            let (mut tx, mut rx) = ws.split();
            ctx.connected.store(true, Ordering::Relaxed);
            ctx.status.update(|s| s.relay_connected = true);
            ctx.status.note(format!("relay connected ({})", url.split("/v1/").next().unwrap_or("")));
            backoff = 1.0;
            loop {
                tokio::select! {
                    m = rx.next() => match m {
                        Some(Ok(Message::Binary(b))) if b.len() > 16 => {
                            let mut src = [0u8; 16];
                            src.copy_from_slice(&b[..16]);
                            let _ = ctx.events.send(Event::Relay(src, b[16..].to_vec())).await;
                        }
                        Some(Ok(Message::Ping(p))) => { let _ = tx.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Close(_))) | None => return Ok(()),
                        Some(Ok(_)) => {}
                        Some(Err(e)) => return Err(e.into()),
                    },
                    out = ctx.outgoing.recv() => match out {
                        Some(frame) => tx.send(Message::Binary(frame.into())).await?,
                        None => return Ok(()),
                    },
                    _ = ctx.stop.notified() => { let _ = tx.send(Message::Close(None)).await; return Err(anyhow::anyhow!("stopped")); }
                }
            }
        }
        .await;
        ctx.connected.store(false, Ordering::Relaxed);
        ctx.status.update(|s| s.relay_connected = false);
        if let Err(e) = &outcome {
            if e.to_string() == "stopped" {
                return;
            }
            tracing::warn!("relay link: {e:#}");
            let mut c = ctx.control.lock().await;
            match e.downcast_ref::<WsError>() {
                Some(WsError::Http(resp)) if resp.status().as_u16() == 401 => c.invalidate_token(), // expired token
                Some(WsError::Http(resp)) if resp.status().as_u16() == 403 => {}                   // not registered here yet
                _ => c.rotate(),
            }
        }
        tokio::select! { _ = tokio::time::sleep(Duration::from_secs_f64(backoff)) => {}, _ = ctx.stop.notified() => return }
        backoff = (backoff * 2.0).min(15.0);
    }
}
