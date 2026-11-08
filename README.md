# nbprefix — read-only prefix browser for NetBox IPAM

Official repository: <https://github.com/rjorgensen123/prefixbrowser>

`nbprefix` shows the prefixes in NetBox as a tree: which prefixes sit under which, how much of each
container is in use, and which blocks are free. You can look at all VRFs as one tree, grouped per VRF,
global prefixes only, or a single VRF (optionally with the global containers that enclose it), and search
by text, IP address or prefix. Every prefix row links straight into NetBox.

## Why this exists

NetBox shows prefixes as a paginated list, and free space one parent prefix at a time. When
you want to see how a block is carved up across a whole VRF, or where the next free block of a given size
is, that means a lot of clicking. `nbprefix` fetches the whole prefix list once and lays it out as a tree
with coverage and free blocks, so the answer is on one screen.

It is a single Python file with no dependencies beyond the standard library, so it can be dropped on any
PC that has Python and network access to NetBox.

## Two things to know

**It runs locally, on each PC.** The script starts a small web server on `127.0.0.1` and opens your
browser. There is no central service and nothing is shared: every user has their own copy, their own
config and their own API token. The server only answers on localhost.

**It is read-only.** It only makes GET requests to the NetBox API (`/api/status/`, `/api/ipam/vrfs/`
and `/api/ipam/prefixes/`) and never changes anything in NetBox. Use a token without write permission.

## Requirements

- Python 3.8 or newer. Standard library only, no `pip install`.
- Network access to the NetBox server and an API token.

## Getting started

1. Put `nbprefix.py`, `VERSION` and `start_nbprefix.bat` in a folder on your PC, together with
   `LICENSE-MIT` and `LICENSE-APACHE`.
2. Start it with `start_nbprefix.bat` (Windows) or `python nbprefix.py`.
3. On first run a dialog asks for the NetBox URL and token. Click **Save and test**.
   The settings are stored in `nbprefix.json` next to the script.

Flags: `--port N` (overrides `port` from `nbprefix.json`, default 8765; if that port is busy, the next free one
up to nine above is used), `--no-browser`, `--version`.

## API token

NetBox 4.5 and newer issue **v2 tokens**. When one is created, NetBox shows the key and the token
separately. Paste either the whole value `nbt_<key>.<token>` into the token field, or the token into the
token field and the key into **Key**. Older NetBox versions use **v1 tokens**
(40 characters), which are pasted as-is. The tool works out which kind it has and sends the right
`Authorization` header: `Bearer` for v2, `Token` for v1.

The token is stored in plain text in `nbprefix.json` on your own PC. That file is in `.gitignore` and
must never be committed.

## Config file (`nbprefix.json`)

| Field        | Description |
|--------------|-------------|
| `netbox_url` | e.g. `https://netbox.example.com` |
| `token`      | API token, v1 or v2 (see above) |
| `token_key`  | Optional, for a hand-edited config: the key part of a v2 token when `token` holds only the token part. The settings dialog merges both into `token`. |
| `verify_tls` | `true` (default) or `false` |
| `ca_file`    | Optional: path to your own CA file (PEM) |
| `port`       | Optional: port for the local web server |

See `nbprefix.example.json`.

## Usage

- **View** (the first drop-down): All VRFs (one tree), All VRFs (grouped per VRF), Global (no VRF), or a
  single VRF. For a single VRF, the global containers that enclose it can be included with **Global containers**.
- **IPv4 / IPv6:** filter by address family.
- **Show free:** shows free blocks (green) between registered prefixes.
- **Search:** free text (prefix, description, tenant, VRF, RD, scope, role, VLAN, status) or an IP address
  or prefix. An IP or prefix search finds the smallest prefix or free block that contains it; if nothing
  does, the prefixes inside the searched range are listed. Esc clears the search.
- **Collapse all / Expand +1 level:** controls how deep the tree is unfolded.
- **Refresh from NetBox:** fetches all prefixes again. Otherwise data is only fetched at startup.
- **Coverage:** the share of a prefix covered by child prefixes, shown for containers and for any prefix
  that has children. The bar turns orange at 90% or more.
- **Children:** the number of direct child prefixes, and the total number of descendants if different.
- A `pool` badge marks prefixes that have *is a pool* set in NetBox.

## Versioning

The version number is in `VERSION` and changes are described in `CHANGELOG.md`.

## Author

**Roger Jorgensen** — rogerj@gmail.com

## License

MIT **or** Apache-2.0, at the recipient's choice.
See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).

Both permit the same use. They differ on patents, and that is the reason for offering both: MIT is
silent on them, Apache-2.0 grants one explicitly and withdraws it from anyone who sues over it (§3).

### Contributions

**Reports are what is wanted here, not patches.** If something behaves differently from what this README
says, open an issue and show how to see it. The tool is deliberately small (one file, no dependencies), and it is quicker for a fix to be made
where development happens than for a patch to be reviewed and reshaped to fit.

Security problems do not belong in a public issue: see [`SECURITY.md`](SECURITY.md).

Code is not refused, but it is accepted only under the same terms as the tool. By submitting code for
inclusion you license it as MIT **or** Apache-2.0, at the recipient's choice, with no additional
conditions. Code offered on other terms cannot be merged, because the choice this tool gives its users
only holds if it holds for every line in it.
