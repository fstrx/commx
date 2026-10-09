//! commx in the browser: a room *member* compiled to WebAssembly.
//!
//! The page is served by the room's host (`commxd --web`), connects back to
//! it over a WebSocket on the same origin, and speaks the normal commx wire
//! protocol: Noise_XX, signed hash chain, sealed room keys. The invite rides
//! in the URL fragment, which browsers never send to any server.
//!
//! Limits, by the nature of browsers: members only (a page can't accept
//! connections), RAM-only identity, and closing the tab is a node drop.

pub mod member;

pub use member::Member;

#[cfg(target_arch = "wasm32")]
mod js {
    use super::Member;
    use wasm_bindgen::prelude::*;

    /// JS handle. Every call returns or queues data; the page moves bytes
    /// between this and the WebSocket.
    #[wasm_bindgen]
    pub struct WebMember {
        inner: Member,
    }

    #[wasm_bindgen]
    impl WebMember {
        #[wasm_bindgen(constructor)]
        /// `password`: for `cx2:` invites; empty string for none.
        pub fn new(invite: &str, alias: &str, password: &str) -> Result<WebMember, JsError> {
            Member::new(invite, alias, (!password.is_empty()).then_some(password)).map(|inner| WebMember { inner }).map_err(|e| JsError::new(&format!("{e:#}")))
        }

        /// Does this invite (`cx2:`) need a password?
        pub fn needs_password(invite: &str) -> bool {
            commx_core::invite::Invite::decode(invite).is_ok_and(|i| i.password)
        }

        pub fn fingerprint(&self) -> String {
            self.inner.fingerprint()
        }

        /// Bytes to send over the WebSocket (may be empty).
        pub fn outgoing(&mut self) -> Vec<u8> {
            self.inner.take_outgoing()
        }

        /// Feed bytes received from the WebSocket.
        pub fn receive(&mut self, data: &[u8]) {
            self.inner.on_bytes(data);
        }

        pub fn closed(&mut self) {
            self.inner.on_close();
        }

        /// JSON array of UI events since the last call.
        pub fn events(&mut self) -> String {
            serde_json::to_string(&self.inner.take_events()).unwrap_or_else(|_| "[]".into())
        }

        pub fn send_text(&mut self, text: &str) -> Result<(), JsError> {
            self.inner.send_text(text).map_err(|e| JsError::new(&format!("{e:#}")))
        }

        pub fn leave(&mut self) {
            self.inner.leave();
        }
    }
}
