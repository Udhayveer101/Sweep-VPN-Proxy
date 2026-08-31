# Getting servers without paying a VPN company

Sweep connects only to WireGuard peers whose key you control. That means a
server has to exist somewhere. These are the free ways to get one, and what each
actually costs you.

## The honest picture

Free tiers cap out at roughly **3–5 servers in 3 countries**. That is not the
same product as a commercial VPN's several hundred relays in 40+ countries — if
you want to look like you are browsing from anywhere, that is what a paid
subscription buys. What a free fleet does give you is servers nobody else shares,
no logging you have to trust, and no monthly bill.

| Provider | Free servers | Regions | Catch |
|---|---|---|---|
| Oracle Cloud Always Free | 2–4 | one region, chosen at signup, **permanent** | card needed for identity check, not charged |
| Google Cloud free tier | 1 | US only | e2-micro, always free |
| AWS free tier | 1 | any region | expires 12 months after signup |
| Fly.io | 2–3 | many | small monthly allowance |

Mixing providers is how you get more than one country.

## Oracle Cloud (best free option)

1. Sign up at cloud.oracle.com. **Choose your home region carefully** — Always
   Free ARM capacity is locked to it forever. Pick the country you most want to
   appear to browse from. Mumbai and Singapore are usually easiest to get
   capacity in from India.
2. Create an **Ampere A1 (ARM)** instance, Ubuntu 22.04, 1 OCPU / 6 GB. This is
   inside Always Free. Upload your SSH public key when asked.
3. In the instance's subnet security list, allow **inbound UDP 51820** and
   **TCP 443** from 0.0.0.0/0.
4. Note the public IP, then from this repo:

```bash
./Tools/sweep-fleet.sh add mumbai ubuntu@<public-ip> IN Mumbai "Oracle Cloud"
```

That provisions WireGuard, the in-tunnel resolver and the firewall, reads the
server key back, adds it to `fleet/fleet.json`, and re-signs the bundle. Rebuild
the app and the server is in the list.

Repeat per machine. Adding the fourth server costs the same as the first.

## Adding more later

```bash
./Tools/sweep-fleet.sh list        # what you have
./Tools/sweep-fleet.sh rebuild     # re-sign after editing fleet.json
```

`fleet/` holds pre-shared keys and is gitignored. So is the signed bundle and
`sweep-config.key` — that private key is what the app trusts, so it never leaves
this Mac.

## If you later want many countries

Buy a Mullvad account (~€5/mo, no email or name required — it issues a random
account number), then:

```bash
swift run --package-path Tools/sweep-catalog sweep-catalog import-mullvad mullvad.json
swift run --package-path Tools/sweep-catalog sweep-catalog merge fleet/bundle.json mullvad.json all.json
```

This adds ~600 relays, marked `requiresAccount`, hidden behind the "Show servers
that need an operator account" toggle. They become usable once this device's
WireGuard key is registered on the account — until then Sweep will not pretend
they work. Your own servers stay the default either way.
