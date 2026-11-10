# Segnalazione al Tor Project — un exit risponde MISC invece di CONNECTREFUSED

**Stato:** analisi completa, patch scritta e verificata; da inviare.
**Dove:** <https://gitlab.torproject.org/tpo/core/tor/-/issues> (componente *Core Tor/Tor*).
**Versione:** tor 0.4.9.13 (`git-3c575400909efe65`), Linux, glibc 2.41.
**Emerso da:** Laboratorio 14 del libro (capitolo 22), `labs/it/laboratorio/politica_uscita.py`.

Questa cartella contiene il testo pronto per l'invio e la patch
(`0001-exit-connectrefused.patch`). Il testo qui sotto, in inglese, è quello da
incollare nella segnalazione. Nella riga `From:` della patch l'indirizzo email è stato
sostituito da un segnaposto (`address-withheld@example.invalid`): prima dell'invio va messo
l'indirizzo con cui firmare il contributo.

---

## Summary

When a connection from an exit relay to its destination is refused, the exit sends the
client a `RELAY_END` cell with reason `MISC` (6) instead of `CONNECTREFUSED` (3). The
correct errno is known to the code at that point — it is even written to the log — but it
is not the value used to choose the reason.

## Steps to reproduce

On a Chutney network (or any exit you control), open a stream from a client to a port on
which nothing is listening, and look at the `RELAY_END` reason.

```
127.0.0.1:8080 -> END reason=EXITPOLICY address=127.0.0.1 TTL=1800   (rejected by policy)
127.0.0.1:8081 -> CONNECTED                                          (server listening)
127.0.0.1:9999 -> END reason=MISC                                    (nothing listening)
```

The third line should be `CONNECTREFUSED`.

The exit's `info` log shows both the right answer and the wrong one, one line apart:

```
[info] connection_handle_write_impl(): in-progress connect failed. Removing.
       (Connection refused)
[info] errno_to_stream_end_reason(): Didn't recognize errno 115 (Operation now in
       progress); telling the client that we are ending a stream for 'misc' reason.
```

## Cause

The outgoing connection is non-blocking, so `connect()` returns `EINPROGRESS` and the
result arrives later as a write event. In `connection_handle_write_impl()`
(`src/core/mainloop/connection.c`) the real error is read into `e`:

```c
if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0) { ... }
if (e) {
  if (!ERRNO_IS_CONN_EINPROGRESS(e)) {
    log_info(LD_NET, "in-progress connect failed. Removing. (%s)",
             tor_socket_strerror(e));
    if (CONN_IS_EDGE(conn))
      connection_edge_end_errno(TO_EDGE_CONN(conn));        /* <-- ignores e */
    if (conn->type == CONN_TYPE_OR)
      connection_or_notify_error(TO_OR_CONN(conn),
                                 errno_to_orconn_end_reason(e),   /* <-- uses e */
                                 tor_socket_strerror(e));
```

`connection_edge_end_errno()` (`src/core/or/connection_edge.c`) recomputes the reason
from scratch:

```c
reason = errno_to_stream_end_reason(tor_socket_errno(conn->base_.s));
```

and on Unix `tor_socket_errno` is the macro `(errno)` (`src/lib/net/socket.h`), i.e. the
global variable, which still holds `EINPROGRESS` (115) from the original `connect()`.
`EINPROGRESS` is not among the cases of `errno_to_stream_end_reason()`
(`src/core/or/reasons.c`), so the `default:` branch returns `END_STREAM_REASON_MISC`.

Note that the two branches in the same `if` block already disagree: the OR branch passes
`e`, the edge branch does not. That asymmetry looks like an oversight rather than a
deliberate choice.

## Effect

Minor, and with no consequence for anonymity: the client learns that the stream failed,
just not why. But it loses information it would otherwise act on — a client that is told
`CONNECTREFUSED` knows the exit reached the destination and that retrying through another
exit is pointless, while `MISC` says nothing. The same path also flattens `NOROUTE`,
`TIMEOUT` and `RESOURCELIMIT` into `MISC`, since any of those errnos would be overwritten
in the same way.

## Suggested fix

Pass the error that is already in hand, exactly as the OR branch does:

```c
if (CONN_IS_EDGE(conn))
  connection_edge_end(TO_EDGE_CONN(conn), errno_to_stream_end_reason(e));
```

`errno_to_stream_end_reason()` is already declared in `core/or/reasons.h`, which
`connection.c` includes.

The other call sites of `connection_edge_end_errno()` are left alone: in the
`getsockopt()` failure branch above there is no valid `e`, and the remaining ones follow
a read or write error, where the global `errno` is the right source.

## Verification

Patch applied to tor 0.4.9.13, rebuilt, and installed on the exit of a private Chutney
network. The same three tests then give:

```
127.0.0.1:8080 -> END reason=EXITPOLICY address=127.0.0.1 TTL=1800
127.0.0.1:8081 -> CONNECTED
127.0.0.1:9999 -> END reason=CONNECTREFUSED
```

The private network is the one described in chapter 19 of the book: 3 directory
authorities, 3 middles, 2 exits, 1 client, 1 onion service, all on 127.0.0.1. No public
relay or user was involved at any point.
