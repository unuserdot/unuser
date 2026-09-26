"""How fresh is Pyth's sponsored SOL/USD account on Solana, and does it exist on devnet?

Reads account 7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE (Pyth receiver PriceUpdateV2, feed SOL/USD, shard 0)
every 2 s (5 s on devnet) for the given number of seconds and prints owner, verification level, feed id, price, conf, exponent,
publish time and its age against the cluster's block time. Read only.
usage: python3 tools/pyth_cadence.py <mainnet|devnet> <seconds>
"""
import base64, json, struct, sys, time, urllib.error, urllib.request

ACC = "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE"
RPC = {"mainnet": "https://api.mainnet-beta.solana.com", "devnet": "https://api.devnet.solana.com"}

def call(url, method, params):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), {"Content-Type": "application/json"})
    for wait in (2, 4, 8, 16, 32):
        try:
            return json.load(urllib.request.urlopen(req, timeout=20))["result"]
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
            time.sleep(wait)  # the free public RPC rate-limits; back off and try again
    raise RuntimeError("rate limited five times in a row")

def parse(d):
    tag = d[40]
    o = 41 if tag == 1 else 42
    feed = d[o:o + 32].hex()
    price, conf, expo, pub, prev = struct.unpack_from("<qQiqq", d, o + 32)
    return {"level": "full" if tag == 1 else f"partial({d[41]})", "feed": feed, "price": price, "conf": conf, "expo": expo, "publish": pub, "prev": prev, "len": len(d)}

net, secs = sys.argv[1], int(sys.argv[2])
url = RPC[net]
t0, last, seen = time.time(), None, []
while time.time() - t0 < secs:
    r = call(url, "getAccountInfo", [ACC, {"encoding": "base64", "commitment": "confirmed"}])
    if not r["value"]:
        print(net, "account missing"); break
    v = r["value"]; d = base64.b64decode(v["data"][0]); p = parse(d)
    slot = r["context"]["slot"]
    bt = call(url, "getBlockTime", [slot]) if last is None or p["publish"] != last else None
    if p["publish"] != last:
        seen.append(p["publish"])
        print(json.dumps({"owner": v["owner"], **p, "slot": slot, "block_time": bt, "age": (bt - p["publish"]) if bt else None}))
        last = p["publish"]
    time.sleep(2 if net == "mainnet" else 5)
if len(seen) > 1:
    gaps = [b - a for a, b in zip(seen, seen[1:])]
    print("updates", len(seen), "gaps s", gaps, "max", max(gaps))
