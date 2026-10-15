# risky-app — the "everything lights up" scan target

Eight completely legitimate, hugely popular packages — zero malware — and
still the answer to "how many packages can read your secrets right now?" is
uncomfortable. Scan it:

```
github.com/Extodan/Capwall-OSS/tree/main/examples/risky-app
```

What you should see (43+ packages):

| stat | count | drivers |
|---|---|---|
| env access | ~13 | axios, dotenv, execa, cross-spawn, debug, which… |
| network | ~7 | axios, follow-redirects, ssh2, esbuild |
| shell | ~6 | cross-spawn, execa, husky, esbuild, ssh2 |
| dynamic code | ~2 | ssh2, google-libphonenumber |
| install scripts | 2 | esbuild, husky |

Headliners: `ssh2` touches **9 of 12 capabilities** (sockets, DNS, env, fs,
shell, dynamic code — it's an SSH client, so that's *why*), `cross-spawn`
and `esbuild` score 100. That's the pitch in one scan: none of this is
malicious, all of it is *unreviewed*, and Capwall is how you make it explicit.
