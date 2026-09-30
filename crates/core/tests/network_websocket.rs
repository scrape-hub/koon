//! Network-required test (`--ignored`) of a WebSocket echo against a public
//! server (the offline HTTP/2 WebSocket suite lives in
//! `tests/websocket_h2.rs`).

use koon_core::*;

#[tokio::test]
#[ignore]
async fn websocket_echo() {
    let client = Client::new(Chrome::latest()).unwrap();
    let ws = client.websocket("wss://echo.websocket.org").await.unwrap();

    // echo.websocket.org sends a welcome message first: consume it.
    let welcome = ws.receive().await.unwrap();
    assert!(welcome.is_some(), "Should receive welcome message");

    ws.send_text("hello koon").await.unwrap();

    let msg = ws.receive().await.unwrap();
    match msg {
        Some(WsMessage::Text(text)) => {
            assert_eq!(text, "hello koon", "Echo should match");
        }
        Some(WsMessage::Binary(data)) => {
            assert_eq!(
                String::from_utf8_lossy(&data),
                "hello koon",
                "Echo should match"
            );
        }
        None => panic!("Expected echo message, got None"),
    }

    ws.close(None, None).await.unwrap();
}
