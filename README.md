# Beacon Hunt

A small, browser-based log analysis exercise. Five workstations and two servers, a short excerpt of firewall and DNS logs, and one machine calling home to a command-and-control (C2) server. Filter the evidence, compare it against the baseline, and pick the compromised host.

Everything runs in a single HTML file with no dependencies. Open `index.html` in a browser.

## How to play

1. Read the asset list and the baseline note.
2. Use the log filters (host, log type, search) to examine the evidence. Selecting a host in the asset table filters the log. It does not choose your answer.
3. Choose the compromised host and check your answer.
4. Read the explanation, the example Sigma rule and the response steps.

Click **New scenario** for a freshly generated one. Hostnames, IP addresses, domains, timing and the compromised host are all random each time.

## What it teaches

- Regular timing alone is not proof of beaconing. Legitimate traffic such as NTP, vendor telemetry and internal health checks is also evenly spaced.
- The stronger evidence is a combination: a burst of failed DNS lookups (NXDOMAIN) for random-looking names, then evenly spaced connections to a destination no other host contacts, with near-identical outbound payload sizes.

## Example detection

`dns-burst.yml` is a Sigma correlation rule that flags a burst of failed DNS lookups from a single host: 4 or more NXDOMAIN responses within 2 minutes, grouped by source address. It is written against Zeek's `dns.log` (`rcode_name`, `id.orig_h`).

It was converted to Splunk SPL with sigma-cli 3.1.0 (pySigma 1.5.1, Splunk backend):

```
sigma convert -t splunk --without-pipeline dns-burst.yml
```

Output:

```
rcode_name="NXDOMAIN"

| bin _time span=2m
| stats count as event_count by _time id.orig_h

| search event_count >= 4
```

### Limits

- The conversion only shows the rule is valid Sigma and converts. **The rule has not been run against live logs.**
- `bin _time span=2m` groups events into fixed 2-minute buckets, not a sliding window. A burst that straddles a bucket boundary can be split into two counts that each fall under the threshold. A real deployment would need tuning.
- No processing pipeline was applied (none of the predefined Splunk pipelines targets Zeek), so the query has no index or sourcetype. Field names depend on how Zeek logs are ingested in your environment.
- Sigma has no way to test for evenly spaced timing. Beacon-interval analysis is a statistical query in your SIEM.

Sigma correlation support varies by backend. See the [Sigma correlation documentation](https://sigmahq.io/docs/meta/correlations.html).

## How it works

The generator (`build(seed)` in `index.html`, between the `GEN` markers) turns a random seed into a scenario: it creates the hosts, adds normal browsing, DNS lookups, a periodic internal health check and a typo, then adds the compromised host's failed-lookup burst and its evenly spaced beacons. The explanation shown after a correct answer is built from the same values, so it always matches the logs.

## Data

All data is synthetic and randomly generated. Public addresses use the ranges reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and domains use the reserved `.example` TLD. No real traffic, organization or employer data is used.

## About this project

This is an original learning exercise inspired by security concepts I studied while preparing for CompTIA CySA+. It is not CompTIA exam content.

I built it with AI assistance (Claude) and then ran the Sigma conversion myself. Automated checks were run during development: generated scenarios were tested for consistency (unique addresses, correct timing and counts) and the page was exercised in a headless browser. It is a beginner exercise, not a production detection.
