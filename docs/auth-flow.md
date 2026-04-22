# VPN Authentication Flow

Based on OpenVPN3 D-Bus protocol. Three entry points, all server-driven.

---

## A. Initial Credentials (pre-connect)

```
Server sends:  StatusChange(major=2/Connection, minor=4/CfgRequireUser, "Username/password credentials needed")
               or StatusChange(major=3/Session, minor=20/SessAuthUserpass, "...")

    status_handler checks needs_credentials() OR needs_user_input()
    │
    ├─► request_credentials()
    │     ├─► UserInputQueueGetTypeGroup() → get (type, group) pairs
    │     ├─► For each: UserInputQueueCheck() → UserInputQueueFetch() → collect slots
    │     │   (username, password, static_challenge — all presented at once)
    │     ├─► Show credentials dialog with all fields
    │     └─► On submit:
    │           ├─► UserInputProvide() for each slot
    │           │   ├─ OK → next slot
    │           │   └─ ERROR "invalid-input" (empty value)
    │           │       └─► show error notification, re-show credentials dialog
    │           ├─► Ready()
    │           │   ├─ OK → Connect() → done, wait for StatusChange
    │           │   └─ ERROR → wait for server signal
    │           └─► Connect()
    │               └─ server sends one of:
    │                   ├─ StatusChange(2, 7/ConnConnected) → ✅ connected
    │                   ├─ StatusChange(2, 11/ConnAuthFailed) → ❌ wrong credentials
    │                   │   └─ status_handler disconnects + shows notification
    │                   └─ StatusChange(2, 4/CfgRequireUser) → dynamic challenge
    │                       └─ see flow B
```

---

## B. Dynamic Challenge (post-connect, during connection)

```
Server sends:  StatusChange(major=2/Connection, minor=4/CfgRequireUser, "Dynamic Challenge")
               + AttentionRequired(type=1, group=5/CHALLENGE_DYNAMIC, "challenge text")

    status_handler checks needs_user_input()
    │
    ├─► UserInputQueueGetTypeGroup() → check (type, group) pairs
    │   ├─ group=1/USER_PASSWORD → dispatch to request_credentials() (more creds needed)
    │   ├─ group=4/CHALLENGE_STATIC → dispatch to request_challenge()
    │   ├─ group=5/CHALLENGE_DYNAMIC → dispatch to request_challenge()
    │   └─ group=6/CHALLENGE_AUTH_PENDING → dispatch to request_challenge()
    │
    └─► request_challenge()
          ├─► UserInputQueueGetTypeGroup() → collect challenge slots
          ├─► Show challenge dialog with server's challenge text
          └─► On submit:
                ├─► UserInputProvide()
                │   ├─ OK → continue
                │   └─ ERROR "invalid-input" → show error, re-show dialog
                ├─► Ready()
                │   ├─ OK → Connect() → done
                │   └─ ERROR → UserInputQueueGetTypeGroup()
                │       ├─ more slots → loop back to request_challenge()
                │       └─ no slots → wait for server signal
                └─► server sends one of:
                    ├─ StatusChange(2, 7/ConnConnected) → ✅ connected
                    ├─ StatusChange(2, 11/ConnAuthFailed) → ❌ auth failed
                    └─ StatusChange(2, 4/CfgRequireUser) → another challenge round
```

---

## C. URL Auth (web browser)

```
Server sends:  StatusChange(major=3/Session, minor=22/SessAuthUrl, "https://...")

    status_handler checks needs_url_auth()
    │
    └─► Show notification + open URL in browser
        (user completes auth in browser, server proceeds automatically)
```

---

## Error Code Summary

| D-Bus Error / StatusChange | Meaning | Action |
|---|---|---|
| `UserInputProvide` → `invalid-input` | Empty value for a required slot | Re-show dialog |
| `UserInputProvide` → `input-already-provided` | Slot already filled | Skip (shouldn't happen) |
| `StatusChange(2, 4)` CfgRequireUser | Server needs user input | Query queue, dispatch by group |
| `StatusChange(3, 20)` SessAuthUserpass | Credentials needed (initial) | Show credentials dialog |
| `StatusChange(2, 11)` ConnAuthFailed | Wrong credentials | Disconnect + notify |
| `StatusChange(2, 7)` ConnConnected | Success | Clear attempt counter |
| `Ready()` error | Not all slots filled yet | Wait for server signal or re-query queue |

---

## ClientAttentionGroup Values (from OpenVPN3 source)

| Group | Value | Meaning |
|---|---|---|
| USER_PASSWORD | 1 | Username/password fields |
| HTTP_PROXY_CREDS | 2 | HTTP proxy credentials |
| PK_PASSPHRASE | 3 | Private key passphrase |
| CHALLENGE_STATIC | 4 | Static challenge (pre-connect, in same batch as creds) |
| CHALLENGE_DYNAMIC | 5 | Dynamic challenge (post-connect, from VPN server) |
| CHALLENGE_AUTH_PENDING | 6 | CR_TEXT auth pending (modern OpenVPN protocol) |

> **Note:** Groups 2 (HTTP_PROXY_CREDS) and 3 (PK_PASSPHRASE) are not handled by the
> current auth dispatch logic. If they appear, `dispatch_for_session()` returns `None`.
