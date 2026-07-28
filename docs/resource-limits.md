# Deterministic resource limits

AssetGuard applies one fixed production resource policy to every scan. The
policy is not read from project YAML, environment variables, or command-line
options. Tests can pass a smaller immutable policy only through private Python
APIs so boundary behavior can be proved without large fixtures or real waits.

Every ceiling is inclusive: an observed value equal to the maximum succeeds,
and the first observed value greater than the maximum fails the entire scan.
AssetGuard does not truncate, sample, skip, downgrade, or partially report
excess input.

| Resource | Inclusive maximum | Unit |
| --- | ---: | --- |
| Rules YAML raw bytes | 1,048,576 | bytes |
| YAML composed nodes | 50,000 | nodes |
| YAML nesting depth | 64 | levels |
| Entries within one directory | 20,000 | entries |
| Total inspected tree entries | 200,000 | entries |
| Total regular files | 100,000 | files |
| Relative path UTF-8 bytes | 4,096 | bytes |
| Relative directory depth | 64 | levels |
| One candidate file | 8,589,934,592 | bytes |
| Aggregate logical candidate bytes | 68,719,476,736 | bytes |
| Texture pixels | 67,108,864 | pixels |
| One OBJ file | 536,870,912 | bytes |
| One raw OBJ logical line | 1,048,576 | bytes |
| One numeric OBJ index token | 32 | ASCII characters |
| Corners in one OBJ face | 65,536 | corners |
| OBJ logical lines | 2,000,000 | lines |
| Total OBJ face corners | 5,000,000 | corners |
| Unique OBJ materials | 65,536 | materials |
| Accumulated issues | 10,000 | issues |
| Members in one duplicate group | 10,000 | members |
| Cumulative issue payload UTF-8 | 33,554,432 | bytes |
| Encoded JSON report | 67,108,864 | UTF-8 bytes |
| Encoded HTML report | 134,217,728 | UTF-8 bytes |
| Existing cache DB plus journal/WAL/SHM | 268,435,456 | bytes |
| Cooperative scan runtime | 1,800 | monotonic seconds |
| Workers | 32 | worker threads |
| In-flight futures | 2 × workers | futures |

## Boundary definitions

The scanned root directory has depth `0`. Every immediate child entry has
depth `1`. A path is measured in its normalized root-relative, forward-slash
form encoded as UTF-8. Unsupported files and directory entries count toward
structural tree limits. An excluded directory entry itself counts, but its
intentionally excluded contents are not traversed. Explicit JSON, HTML, cache,
and cache-sidecar file exclusions count as tree entries but not scan candidate
files.

Every lexical regular-file path counts independently. Hardlinks therefore
count once per lexical path. Candidate size is the non-following `st_size`
recorded during structural preflight, and aggregate size is the sum of that
logical size for every candidate path. AssetGuard records device, file ID,
size, and modification time, compares opened-handle metadata while hashing,
and rechecks paths after reads. Replacement, growth, shrinkage, or detectable
metadata change fails through the operational error boundary.

Rules are read in binary with one bounded read of at most 1,048,577 bytes,
then decoded as UTF-8. Safe-loader parser events enforce node and depth limits
before object construction. The root YAML node is depth `1`; each child node
adds one level. Anchors and aliases retain PyYAML safe-loader semantics. An
alias reuses its anchored composed node and is not counted as another composed
node.

OBJ files are opened in binary mode. A logical record is the byte sequence
returned by bounded binary `readline`, so a terminating LF counts as one byte
and a CRLF terminator counts as two bytes. An unterminated final record counts
only its bytes. The line ceiling is checked before UTF-8 decoding or token
allocation. Face tokens are streamed, and numeric index length is checked
before integer conversion. Blank and comment-only records count toward the
logical-line ceiling.

Texture pixel accounting checks `height > maximum // width` before accepting
the product. Pillow decompression-bomb warnings and errors are converted to the
same typed resource-limit failure. AssetGuard does not change Pillow's
process-global pixel setting.

Issue payload accounting uses the compact, sorted-key, UTF-8 JSON encoding of
each public issue object. JSON and HTML output builders count their exact UTF-8
encoding incrementally. Both reports are fully rendered and written to bounded
temporary files before cache commit or atomic replacement, so a resource
failure cannot replace an existing report.

Before any SQLite connection or integrity check, AssetGuard lexically validates
and sums the database and its recognized `-journal`, `-wal`, and `-shm`
sidecars. Cache keys derive from both the file-content SHA-256 and the complete
resource-policy fingerprint. A pre-policy cache row is consequently a safe
miss. Content resource validation still runs before every cache lookup. Cache
state is snapshotted within the fixed cache ceiling and restored on failure;
new cache and sidecar files are removed. Growth is checked before successful
commit without changing the public SQLite schema.

## Cooperative runtime and failures

One `time.monotonic()` budget begins at CLI scan entry, before rules or scan-root
access. Checkpoints cover rules parsing, traversal, hashing chunks, OBJ records,
texture inspection, worker submission and ordered collection, issue and cache
work, report construction, temporary publication, and cache commit. On failure,
queued futures are cancelled, running workers observe the shared stop request,
and the executor is drained before the exception returns.

This is a cooperative deadline. It does not claim to interrupt a thread blocked
inside a kernel filesystem operation, image decoder, or SQLite call. The next
checkpoint detects an overrun, and AssetGuard never uses signals, subprocesses,
unsafe thread termination, or background workers that survive CLI exit.

Every resource violation produces exit code `2`, exactly one concise `Error:`
line, no traceback or success output, and stable wording containing the
resource, observed value, inclusive limit, and a normalized project-relative
path only when a path is necessary.
