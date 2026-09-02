# Relay list mirror

The app fetches the VPN Gate public relay list from `vpngate.net`. Some networks
block that domain by category — an Indian residential ISP answers with a 403
block page from its own gateway:

```
http://www.vpngate.net/api/iphone/ → 403 from 10.1.2.3:8090 (webcat, cat=1048)
```

This Worker refetches the same public CSV from Cloudflare's network and serves
it from `*.workers.dev`, which those filters do not categorise.

```bash
cd Tools/relay-mirror
npx wrangler deploy
```

Paste the resulting URL into **Mirror URL…** in the app's public-relay picker.
The app tries your mirror first and falls back to the official endpoint.

It proxies a file VPN Gate already publishes publicly, keeps no logs and holds
no state, so it does not learn anything about you that a direct fetch would not
have told vpngate.net anyway.
