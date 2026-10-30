# Delta cursor compatibility

`pull_deltas` and `FederationPoller` accept `cursor_mode="exclusive"` (the default)
or `cursor_mode="inclusive"`. Choose the mode from the peer's documented contract
and retain it with the cursor. Never switch modes on an existing cursor without
an explicit conversion.

| Mode | Peer filters | Cursor after a nonempty page | Empty page |
| --- | --- | --- | --- |
| `exclusive` | `seq > since` | Last received sequence | Input cursor retained |
| `inclusive` | `seq >= since` | Last received sequence + 1 | Input cursor retained |

The built-in `create_sm_router` and `DeltaStore.since` use the exclusive filter.
The router's legacy `next_seq` is the store's next assignable sequence, not a safe
exclusive polling cursor; the default client derives its cursor from the returned
rows. This preserves existing client behavior and avoids skipping a concurrent
append that appears in the store counter after the page was read.

Crushnet's index has a separate inclusive route. For that contract:

```python
poller = FederationPoller(
    "https://reviewed-peer.example", store,
    cursor_mode="inclusive", fetch=authenticated_fetch,
)
result = poller.sync_once()
```

Inclusive mode requires an integer `next_seq` exactly equal to the derived cursor.
It refuses cursor jumps, rewinds and advancing empty pages. Both modes validate
strictly increasing integer sequences in the requested range, known actions and
every agent before writing any row. All local proof re-verification also completes
before writes; peer claims still default to `NOT_VERIFIED`.

Keep polling with the returned cursor. A short nonempty page may reflect a byte
budget and does not prove the feed is exhausted. This API fetches one page per call.

These checks do not prove a peer returned every entry: sequence gaps can exist and
an unauthenticated feed can lie. They also do not make writes atomic. A store error
mid-page can leave some writes applied without advancing the poller's cursor. A
production importer needs a transactional sink with durable peer cursor, replay
deduplication and recovery. The default transport's body limits, authenticated peer
identity, durable import and production federation remain separate work. This
change does not upgrade a consuming application's dependency or enable any peer.
