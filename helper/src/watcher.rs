//! Watches the GUI's D-Bus name owner. When the name disappears
//! (GUI crash or clean exit), the helper auto-removes kill-switch
//! rules so the user is never locked out of the network.
//!
//! The helper is a system D-Bus service, so it watches `NameOwnerChanged`
//! on the system bus — the GUI's unique name (`:1.N`) on that bus
//! disappears the moment its process dies.
//!
//! The async D-Bus glue is intentionally untested (no branching logic);
//! the testable surface is [`is_disappearance`].

use anyhow::{Result, bail};
use futures::stream::StreamExt;
use zbus::Connection;
use zbus::fdo::DBusProxy;

/// Block until `bus_name` loses its owner on `conn`. Returns `Ok(())` when
/// the name's `new_owner` becomes empty (the GUI process died or quit).
///
/// Errors if the D-Bus subscription fails or the signal stream terminates
/// before the watched name disappears.
pub async fn wait_for_disappearance(conn: &Connection, bus_name: &str) -> Result<()> {
    let dbus = DBusProxy::new(conn).await?;
    let mut stream = dbus.receive_name_owner_changed().await?;

    while let Some(signal) = stream.next().await {
        let args = signal.args()?;
        let new_owner = args.new_owner.as_ref().map(zbus::names::UniqueName::as_str);
        if is_disappearance(bus_name, args.name.as_str(), new_owner) {
            return Ok(());
        }
    }
    bail!("NameOwnerChanged stream ended before {bus_name} disappeared");
}

/// True if the `NameOwnerChanged` event indicates `watched` lost its owner.
pub fn is_disappearance(watched: &str, name: &str, new_owner: Option<&str>) -> bool {
    name == watched && new_owner.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_disappearance_of_watched_name() {
        assert!(is_disappearance(":1.42", ":1.42", None));
    }

    #[test]
    fn ignores_other_names_disappearing() {
        assert!(!is_disappearance(":1.42", ":1.99", None));
    }

    #[test]
    fn ignores_name_appearance() {
        assert!(!is_disappearance(":1.42", ":1.42", Some(":1.42")));
    }

    #[test]
    fn ignores_owner_change_to_new_value() {
        assert!(!is_disappearance(
            "net.example.app",
            "net.example.app",
            Some(":1.99")
        ));
    }
}
