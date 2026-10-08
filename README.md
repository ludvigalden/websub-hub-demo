# websub-hub-demo

A small Go demonstration of [WebSub](https://www.w3.org/TR/websub/)
subscription verification and HMAC-signed delivery. It implements a
deliberately restricted, single-topic subset for trusted local use. It needs
Go 1.26 or later and uses only the standard library.

The Compose setup runs the hub next to
[`modfin/websub-client`](https://hub.docker.com/r/modfin/websub-client),
a prebuilt subscriber that is used here as a demo fixture.

## Quick start

```sh
docker compose up --build
```

The subscriber registers with the hub on startup. Wait until the hub logs a
line with `msg=verified`, then trigger a notification from another terminal:

```sh
curl -X POST http://127.0.0.1:8080/publish
# {"event_id":"3OYC5D7YZIXMLW2FJL6BTWTSPR","selected":1,"attempted":1,"acknowledged":1,"failed":0,"skipped_expired":0,"not_attempted":0}

curl http://127.0.0.1:8081/log
```

Check that the returned `event_id` appears in the subscriber's `/log` page.
The subscriber lists only messages whose signature it could verify, so this is
the end-to-end check.

The subscriber image is pinned by digest to the revision this demo was tested
against. It is published for `linux/amd64` only. On non-amd64 hosts, the
subscriber requires amd64 emulation, provided by Docker Desktop or configured
separately. The hermetic Go tests are the stable
correctness check; the Compose run is additional integration evidence.

## Security

Run this only where everyone who can reach the hub is trusted. The hub has no
API authentication: anyone who can reach it can register any callback URL and
trigger broadcasts. Intent verification only shows that a callback echoed a
challenge, and the HMAC signature only lets a subscriber check that a payload
came from the hub. Neither authorizes callers or restricts which destinations
the hub contacts. The hub fetches registered callback URLs before intent is
established, with no address filtering, so it will make requests to anything
it can reach. Compose publishes both services on `127.0.0.1` only.

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

| Endpoint        | Behaviour                                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| `POST /`        | Subscription request (`application/x-www-form-urlencoded`). Returns `202`, then verifies the callback. |
| `POST /publish` | Generates a new event, delivers it to active subscriptions, and returns a summary.                     |

### Subscription

- The request must carry `hub.mode=subscribe`, an absolute http(s)
  `hub.callback` with a host, `hub.topic=a-topic`, and a `hub.secret` of 1 to
  199 bytes. A `hub.lease_seconds` parameter, if present, must be a positive
  integer. The hub always grants a fixed 24-hour lease.
- Two of these are demo restrictions rather than WebSub rules: WebSub topics
  are URLs and the secret is optional. This hub serves only the fixed topic
  `a-topic` and requires a secret, because every delivery is signed.
- The callback must not contain a literal `#`, even an empty fragment; a
  percent-encoded `%23` is fine.
- Invalid requests get `400`, a wrong media type gets `415`, and a body over
  16 KiB gets `413`. When the hub is at capacity or shutting down it answers
  `503` and admits no verification.
- The `202` is written and flushed before the hub contacts the callback. That
  fixes the order on the hub's side only; the network does not guarantee the
  subscriber processes the response first. If the flush fails, the hub logs it
  and verifies anyway, since the challenge alone decides the outcome.
- The hub then sends a GET to the callback with `hub.mode`, `hub.topic`,
  `hub.challenge` and `hub.lease_seconds` appended to any existing query. The
  subscription becomes active only if the response is `2xx` and its body is
  exactly the challenge. Redirects are not followed. The lease is measured from
  the start of the verification request.
- Overlapping requests for one callback each get an increasing revision. A
  successful verification is committed only if no newer revision has already
  verified, so a slow older verification cannot overwrite a newer secret, and a
  failed newer attempt leaves the working subscription in place.

### Delivery

- Each accepted publish creates a new event. Its JSON body is serialized once,
  and every recipient gets those exact bytes signed with its own secret.
- Recipients are the active subscriptions when the broadcast starts, ordered
  by their current revision, so a renewal moves a subscription to the end.
  Each broadcast starts one position later in that order than the previous
  one. Delivery is sequential, one attempt per recipient, with a 5-second
  timeout per attempt and an 8-second budget for the whole broadcast. A
  failing recipient does not stop delivery to the rest while budget remains.
- There is no fairness guarantee beyond that rotation. Two recipients that
  stall for the full timeout use up a broadcast's budget, and everyone after
  them is not attempted. The rotation moves the start each time, so stalled
  recipients do not always come first, but with many stalled recipients most
  broadcasts can still miss a healthy one. `not_attempted` reports this.
- Just before each attempt the hub re-reads that recipient's current
  subscription, so a renewal committed mid-broadcast is signed with the new
  secret. A renewal can still commit right after that read; secret rotation is
  not atomic with delivery.
- Delivery belongs to the publish request. If the caller disconnects or the
  budget runs out, the attempt in progress is canceled and the remaining
  recipients are not attempted. Send `/publish` without a body: the hub
  ignores one, and an unread body can delay noticing that the caller left.
- Concurrent publishes are independent: they can deliver to the same
  subscriber at the same time, and there is no ordering between events. There
  are no retries, no persistence, and no exactly-once delivery.

The summary counts recipients:

| Field             | Meaning                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------- |
| `selected`        | Active when the broadcast started.                                                       |
| `attempted`       | A delivery request was started.                                                          |
| `acknowledged`    | The subscriber answered `2xx`. This proves receipt, not processing or a valid signature. |
| `failed`          | No `2xx` was obtained. The subscriber may still have received the payload.               |
| `skipped_expired` | The subscription expired or was removed before its turn.                                 |
| `not_attempted`   | The broadcast was canceled or ran out of budget before its turn.                         |

`selected = attempted + skipped_expired + not_attempted` and
`attempted = acknowledged + failed` always hold.

### Limits and shutdown

- At most 16 verifications run at once and at most 1000 distinct callbacks
  are stored or being verified. Both limits are checked before the `202` is
  sent. A callback counts once whether it is stored, being verified, or both,
  so renewing a stored callback never counts against the storage limit.
- At most 4 publishes run at once. Another publish gets `503` immediately,
  before an event is generated; there is no queue. Together with the
  verification limit, the hub has at most 20 callback requests in flight.
- Expired subscriptions are removed when a subscription request or publish
  arrives, except while a verification for the same callback is still
  outstanding.
- The server limits header reads to 5 seconds, whole-request reads to 10
  seconds, and idle connections to 60 seconds. Its write timeout leaves room
  for the broadcast budget.
- On `SIGINT` or `SIGTERM` the hub stops accepting connections and admits no
  new verification or publish; a verification admitted just before may still
  start afterwards. It then waits up to nine seconds for in-flight
  requests and admitted verifications to finish, and exits `0`. If work is
  still running at the deadline, the hub exits `1` without waiting for it.
  Nine seconds fits inside Docker's default 10-second stop timeout.

## Non-goals

This demo deliberately leaves out:

- unsubscription and topic discovery
- persistence across restarts
- delivery retries
- `Link` headers
- protection against server-side request forgery
- the rest of full WebSub conformance

Restarting the hub loses its subscriptions, so recreate both services together
with `docker compose up --force-recreate`.

## Code layout

All code is in one package:

- `main.go`: flags, logging, signal handling and the shutdown sequence
- `http.go`: routes, request parsing and validation, responses, server timeouts
- `hub.go`: admission and capacity, verification, signed delivery and the
  broadcast loop
- `types.go`: the data types, limits, and small accessors for locked state

## Development

```sh
go vet ./...
go test -race ./...
```

The tests are hermetic: every callback is a local `net/http/httptest` server,
and the hub's client refuses any other destination. They force interleavings
with channels instead of sleeps; timeouts serve only to fail a stuck test. They
cover:

- input validation and status codes
- acceptance flushed before verification starts
- exact challenge matching and redirect handling
- callback query preservation
- per-subscriber signatures, checked independently of the hub's signing code,
  sent as `POST` with `Content-Type: application/json`
- partial failure, caller cancellation and the broadcast budget
- the rotating broadcast start, and the publish limit
- renewal during a broadcast, and revision ordering
- lease expiry, and reclaiming expired records while verifications overlap
- verification and storage limits, including a pending renewal
- a failed acceptance flush
- failure diagnostics that do not log callback URLs
- shutdown draining an in-flight publish and verification, and giving up at
  the deadline
- the built program draining a publish on `SIGTERM`, and its exit status

## License

[MIT](LICENSE)
