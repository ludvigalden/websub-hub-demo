# websub-hub-demo

A minimal [WebSub](https://www.w3.org/TR/websub/) hub in Go. It verifies
subscriber intent, keeps verified subscriptions in memory, and broadcasts
HMAC-SHA-256-signed JSON notifications. It is a single file built on the
standard library alone, with no dependencies.

The Compose setup runs the hub next to
[`modfin/websub-client`](https://hub.docker.com/r/modfin/websub-client),
a prebuilt subscriber that is used here as a demo fixture.

## Quick start

```sh
docker compose up --build
```

The subscriber registers with the hub on startup. Once the hub logs
`msg=verified subscription=1`, trigger a notification from another terminal:

```sh
curl -X POST http://localhost:8080/publish
# {"event_id":"3OYC5D7YZIXMLW2FJL6BTWTSPR","selected":1,"attempted":1,"acknowledged":1,"failed":0,"skipped_expired":0}

curl http://localhost:8081/log
```

The subscriber's `/log` page lists only messages whose signature it could
verify, so this is the end-to-end check.

The subscriber image is published for `linux/amd64` only. On other
architectures Docker needs amd64 emulation to run it.

## How it works

```text
subscriber ── POST / (form) ──────────────▶ hub      202 Accepted
hub ───────── GET callback?hub.challenge=… ▶ subscriber
subscriber ── challenge, verbatim ─────────▶ hub      subscription becomes active

operator ──── POST /publish ───────────────▶ hub
hub ───────── POST callback ───────────────▶ each active subscriber
              Content-Type: application/json
              X-Hub-Signature: sha256=HMAC(secret, body)
```

| Endpoint        | Behaviour                                                                                                              |
| --------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `POST /`        | Subscription request (`application/x-www-form-urlencoded`). Returns `202` and verifies the callback in the background. |
| `POST /publish` | Generates one JSON event, delivers it to every active subscription, and returns a delivery summary.                    |

### Subscription

- The request must carry `hub.mode=subscribe`, an absolute http(s)
  `hub.callback`, `hub.topic=a-topic`, and a `hub.secret` of 1 to 199 bytes.
  A `hub.lease_seconds` value, if present, must be a positive integer. The
  hub always grants a fixed 24-hour lease.
- Invalid requests get `400`, a wrong media type gets `415`, and a body over
  16 KiB gets `413`.
- Acceptance does not activate the subscription. The hub sends a GET to the
  callback with `hub.mode`, `hub.topic`, `hub.challenge` and
  `hub.lease_seconds` appended to any existing query. The subscription becomes
  active only if the response is `2xx` and its body is exactly the challenge.
  Redirects are not followed.
- The lease is measured from the start of the verification request.

### Delivery

- The JSON body is serialized once. Each recipient gets those exact bytes,
  signed with its own secret.
- Delivery is sequential, one attempt per subscriber, with a 5-second timeout.
  A failing subscriber does not stop delivery to the rest.
- Leases are checked when the recipient list is taken and again before each
  send. The summary reports `selected`, `attempted`, `acknowledged` (a `2xx`
  reply), `failed`, and `skipped_expired`.

### Concurrency

Subscriptions are keyed by callback URL in a mutex-guarded map. The lock is
never held during network I/O.

A mutex alone does not decide which of two overlapping re-subscriptions should
win. Each accepted request therefore gets an increasing revision number, and a
successful verification is committed only if no newer revision has already
verified for that callback. A slow, older verification cannot overwrite a newer
secret. A failed newer attempt never invalidates a working subscription.

## Non-goals

This demo deliberately leaves out:

- unsubscription and topic discovery
- persistence across restarts
- delivery retries
- `Link` headers
- the rest of full WebSub conformance

The hub serves a single fixed topic. Restarting the hub loses its subscriptions,
so recreate both services together with `docker compose up --force-recreate`.

Callbacks are fetched from inside the Compose network without any address
filtering. That is fine for a local demo, but a public deployment would need
protection against server-side request forgery.

## Development

```sh
go vet ./...
go test -race ./...
```

The tests run fake subscribers built with `net/http/httptest`. They cover:

- input validation and status codes
- acceptance before verification
- exact challenge matching and redirect handling
- callback query preservation
- per-subscriber signatures, checked independently of the hub's signing code
- partial delivery failure
- revision ordering
- lease expiry, before and during a broadcast
- concurrent subscribe and publish

## License

[MIT](LICENSE)
