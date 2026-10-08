# websub-hub-demo

A small [WebSub](https://www.w3.org/TR/websub/) hub in Go, written as a
take-home case. It works with the prebuilt
[`modfin/websub-client`](https://hub.docker.com/r/modfin/websub-client)
subscriber and implements only what the case asks for: subscription with intent
verification, signed delivery, and an endpoint that publishes generated JSON.

It uses only the standard library. The code is `hub.go` (the hub) and `main.go`
(the server and shutdown), plus tests in `hub_test.go`.

## Run it

```sh
docker compose up --build
```

The client subscribes on startup. Wait until the hub logs `INFO verified`, then
publish an event from another terminal:

```sh
curl -X POST http://127.0.0.1:8080/publish
# {"delivered":1,"event_id":"3OYC5D7YZIXMLW2FJL6BTWTSPR","subscribers":1}

curl http://127.0.0.1:8081/log
```

The `event_id` should appear in the client's `/log`. The client lists only
messages whose signature it could verify, so this is the end-to-end check.

Compose follows the case's example, with four differences:

- The hub is built from the repository root instead of `./hub`, and no source
  volume is mounted.
- Both ports are bound to `127.0.0.1` because the hub has no authentication.
- The client image is pinned by digest to the `latest` build this was tested
  against, so a new upload cannot change the demo.
- `platform: linux/amd64` is set because that image is published only for
  amd64.

The demo relies on the client's automatic subscribe at startup. The hub keeps
subscriptions in memory, so after restarting it, recreate both services with
`docker compose up --force-recreate`.

## How it works

```text
client ── POST /  hub.mode=subscribe … ─────▶ hub    202 Accepted
hub ───── GET callback?hub.challenge=… ─────▶ client
client ── 200, body = challenge ────────────▶ hub    subscription stored

you ───── POST /publish ────────────────────▶ hub
hub ───── POST callback ────────────────────▶ each live subscriber
          Content-Type: application/json
          X-Hub-Signature: sha256=hex(HMAC-SHA256(secret, body))
```

- **Registration.** `POST /` takes a form with `hub.mode=subscribe`,
  `hub.topic`, an absolute http(s) `hub.callback`, `hub.secret` and an
  optional `hub.lease_seconds`. The default lease is 24 hours. Invalid input
  gets `400`. Anything else gets `202`, and verification runs in the
  background.
- **Intent verification.** The hub sends a GET to the callback and appends
  `hub.mode`, `hub.topic`, a random `hub.challenge` and `hub.lease_seconds` to
  the callback's existing query. It stores the subscription only on a `2xx`
  response whose body is exactly the challenge. Redirects are not followed,
  since that would let a different URL answer, and every callback request
  times out after 5 seconds.
- **Signing.** Each event is marshaled once, and every subscriber gets those
  exact bytes, signed with its own secret. The secret is optional in WebSub;
  it is required here because the case asks for every message to be signed.
- **Publish.** `POST /publish` generates an event and posts it to every
  subscription whose lease has not expired. It returns the event id, the
  number of subscribers, and the number that answered `2xx`.
- **Concurrency.** `net/http` runs handlers concurrently, so one mutex guards
  the subscription map. It is held only to read or write the map, never during
  a network call. Each registration gets a sequence number when it arrives. If
  two verifications for the same callback overlap, a slower, older one cannot
  overwrite a newer secret.

## Scope

Only the case's requirements are implemented. There is no unsubscribe, no
discovery (`Link` headers), no persistence, and no content distribution from
a real publisher. A subscription request with any other `hub.mode` is
rejected with `400`.

## What I'd add next

These are deliberately left out to keep the code small:

- **Unsubscribe and lease renewal**: the other half of the subscription
  lifecycle.
- **Delivery retries** with backoff, and a durable queue, so a subscriber that
  is briefly down does not miss events.
- **Persistence** of subscriptions, so they survive a restart.
- **Parallel fan-out** with a concurrency limit and an overall publish
  deadline. Delivery is currently sequential, so one slow subscriber delays
  the rest by up to 5 seconds.
- **Capacity limits**: a cap on pending verifications, stored subscriptions,
  and concurrent publishes, so registrations cannot exhaust the hub.
- **Cleanup of expired subscriptions.** They are skipped today but stay in
  memory.
- **Outbound request filtering against SSRF.** The hub currently calls any URL
  it is given, including internal addresses.
- **Graceful shutdown that also waits for background verifications.** Today it
  waits only for in-flight HTTP requests.
- **Structured, privacy-aware logging.** Callback URLs can carry tokens, so
  production logs should not print them as they are.

## Development

The code needs Go 1.26 or later.

```sh
go vet ./...
go test -race ./...
```

The tests are hermetic: every subscriber is a local `httptest` server. They
cover:

- input validation;
- that a verified subscription is stored and that the callback's query is
  preserved;
- that a wrong challenge, a non-`2xx` response, or a redirect does not store a
  subscription;
- that the lease is counted from the verification request;
- that a stale verification cannot overwrite a newer one;
- the signature, checked independently over the exact delivered bytes, along
  with the method and `Content-Type`;
- that expired subscriptions are skipped;
- concurrent subscribe and publish under the race detector.

## License

[MIT](LICENSE)
