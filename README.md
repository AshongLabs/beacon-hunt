# Beacon Hunt

**Beacon Hunt is a short, hands-on exercise for learning how security analysts spot an infected computer by reading network logs.**

You get a small network: five workstations (everyday employee computers) and two servers. You also get a short excerpt of the logs that the network's firewall and DNS server recorded. One of those machines has been infected with malware and is secretly "calling home" to an attacker's server. Your job is to work out which one, using only the evidence in the logs.

You don't need any security experience to try it. The glossary below explains every term, and the page itself explains the answer after you guess.

Everything runs in a single web page. There is nothing to install and no account to create. Just open `index.html` in a browser.

## Who is this for?

- People studying for entry-level security certifications such as CompTIA Security+ or CySA+ who want practice reading logs.
- Beginners who have heard terms like "beaconing" or "command and control" and want to see what they actually look like.
- Anyone curious about how defenders find malware without ever touching the infected machine.

## Glossary

| Term | What it means |
|---|---|
| **Log** | A running record of events, one line per event, like a receipt for everything that happened on the network. |
| **Firewall** | A security device or program that decides which network connections are allowed and records them. In this exercise, firewall lines show who connected to what, and how much data was sent. |
| **DNS** | The internet's phone book. When a computer wants to visit a name like `example.com`, it asks a DNS server for the matching number, called an IP address. |
| **IP address** | The numeric address of a computer on a network, such as `10.20.4.37`. |
| **NXDOMAIN** | A DNS reply that means "that name does not exist." A few of these are normal (typos). Many in a row are suspicious. |
| **Malware** | Malicious software. |
| **C2 / command-and-control server** | A server run by an attacker. Infected computers contact it to receive instructions or to report in. |
| **Beaconing** | An infected computer "checking in" with its C2 server again and again, usually at regular intervals, like a heartbeat. |
| **DGA (domain generation algorithm)** | A trick some malware uses: it generates lots of random-looking domain names and tries them one by one until it finds one the attacker has set up. This is why an infected machine can produce many failed lookups for strange names. |
| **Baseline** | A description of what *normal* looks like on a network. You can only spot what's strange if you know what's expected. |
| **Payload size** | How much data a single connection sent. |
| **Sigma** | An open, shared format for writing detection rules in plain text (YAML). A Sigma rule can be converted into the search language of different security tools. |
| **SIEM** | A security tool that collects logs from many places and lets analysts search them and raise alerts. Splunk and Elasticsearch are examples. |
| **Zeek** | A free network monitoring tool that writes detailed logs, including one for DNS (`dns.log`). |
| **Synthetic data** | Made-up data created for practice. Nothing in this exercise comes from a real network. |

## How to play

1. **Read the asset list.** It lists the seven machines with their names, IP addresses and roles. The logs show IP addresses, not names, so use this table to translate.
2. **Read the baseline note.** It tells you about one kind of traffic that is expected and safe, so you don't mistake it for an attack.
3. **Read the log excerpt.** Each line is one event.
   - Firewall lines look like: `07:42:10 fw  10.20.4.37 > 203.0.113.9:443 out=312 dom=example.example`. That means: at 07:42:10, the machine `10.20.4.37` connected to `203.0.113.9` on port `443`, sent `312` bytes, and the domain involved was `example.example`.
   - DNS lines look like: `07:42:09 dns 10.20.4.37 example.example NOERROR 203.0.113.9`. That means: at 07:42:09, `10.20.4.37` asked for the address of that name, and the DNS server answered successfully (`NOERROR`) with that IP. A result of `NXDOMAIN` means the lookup failed because the name doesn't exist.
4. **Filter the evidence.** Above the log you can pick a host, show only DNS or only firewall lines, or search for any text such as `NXDOMAIN` or an IP address. You can also click a host in the asset table to filter the log to that host. Filtering is just for investigating: it does **not** pick your answer. **Expand log** shows the whole log at once.
5. **Choose the compromised host** and press **Check answer**. Stuck? The **Hint** button gives you a nudge without giving it away.
6. **Read the explanation.** After a correct answer, the page shows exactly why that host is infected, why the lookalike machines are not, an example detection rule, and what a team would do next.
7. Press **New scenario** to try again. Hostnames, addresses, domains, timing and the infected machine are all randomized each time.

<details>
<summary>Spoiler-light guide: what to look for</summary>

- **Regular timing alone isn't enough.** Plenty of harmless things happen on a schedule. Look for who else does the same thing.
- **Look at who talks to what.** A destination that only one machine ever contacts deserves a closer look.
- **Check the DNS log for failures.** A burst of failed lookups for random-looking names, just before a machine starts talking to a new destination, is a classic sign.
- **Compare payload sizes.** Beacons often send nearly the same tiny amount of data every time.
- **Use the baseline** to rule out expected traffic.
</details>

## What you'll learn

- **Regular timing alone is not proof of beaconing.** Time servers, vendor software and internal health checks are all evenly spaced too. Real analysts avoid jumping to conclusions from one clue.
- **Evidence is stronger in combination.** The infected machine in this exercise shows several signs together: a burst of failed lookups for random-looking names, then evenly spaced connections to a destination no other machine contacts, each sending nearly the same small amount of data.
- **How to separate the unusual from the normal** by using a baseline and by filtering and comparing logs.
- **How a human finding becomes an automatic detection** through a rule written in Sigma.

## The example detection rule

After you answer correctly, the page shows an example detection rule. A version of it is saved in this repository as `dns-burst.yml`.

**What it does:** it raises an alert when a single machine has **4 or more failed DNS lookups within 2 minutes**. A single typo won't trigger it, but a burst of failures will, which matches how malware that generates random domain names behaves.

**Technical details:** it is a Sigma *correlation rule* written for Zeek's `dns.log`. It counts events where `rcode_name` is `NXDOMAIN`, grouped by the source address `id.orig_h`, over a 2-minute window.

I converted it into a Splunk search using the Sigma command-line tool (sigma-cli 3.1.0 with pySigma 1.5.1 and the Splunk backend):

```
sigma convert -t splunk --without-pipeline dns-burst.yml
```

It produced:

```
rcode_name="NXDOMAIN"

| bin _time span=2m
| stats count as event_count by _time id.orig_h

| search event_count >= 4
```

Reading that query from top to bottom: find the failed lookups; sort them into 2-minute time blocks; count them for each source machine in each block; keep only the blocks with 4 or more.

### Honest limits

This is a learning example, not a ready-to-use detection. Please read these before reusing it:

- **It has not been run against real logs.** The conversion only proves the rule is valid Sigma and that the tool can translate it.
- **Time blocks are fixed.** `bin _time span=2m` cuts time into set 2-minute blocks instead of a moving window. A burst that straddles the edge of two blocks can be split into two counts that are each too low to alert. A real deployment would need tuning.
- **No log location is specified.** I used `--without-pipeline`, because none of the predefined Splunk pipelines is designed for Zeek. A *pipeline* is a set of translation settings that tells the tool where your logs live and what fields are called. As a result, the query doesn't say which Splunk index or sourcetype to search, and your field names may differ depending on how your Zeek logs are collected.
- **Sigma can't check for even spacing.** Sigma can count events, but it has no way to test whether connections are evenly spaced in time. Spotting regular beacon intervals is a statistical job done in your SIEM.
- **Backend support varies.** Not every tool supports Sigma correlation rules. See the [Sigma correlation documentation](https://sigmahq.io/docs/meta/correlations.html).

## How it works

The page contains a small generator, the `build(seed)` function in `index.html` (between the `GEN` markers). Starting from a random number (the *seed*), it builds a scenario step by step:

1. It invents seven hosts with random names and IP addresses.
2. It adds normal traffic: a little web browsing, DNS lookups for each site visited, and a steady internal health check between the two servers.
3. It adds one harmless typo (a single failed lookup) on a different machine, as a decoy.
4. It picks one host to be infected. That host fails several lookups for random names, then starts contacting a made-up C2 domain at a steady interval, always sending a similar small amount of data.
5. It sorts every event by time and displays them as the log.

The explanation shown after a correct answer is generated from the same values, so it always matches the log you were looking at.

## About the data

Everything is synthetic and randomly generated. Public IP addresses come from the ranges reserved for documentation (192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24), and domain names use the reserved `.example` ending, so none of them point to real systems. No real network traffic, business data or employer data is used.

## About this project

This is an original learning exercise, inspired by security concepts I studied while preparing for the CompTIA CySA+ certification. It is not CompTIA exam content and is not affiliated with CompTIA.

I vibecoded this with the assistance of Claude. I then ran the Sigma conversion on my computer. Numerous checks were run during development: generated scenarios were tested for consistency (unique addresses, correct timing and counts) and the page was exercised in a web browser. It is a beginner exercise, not a production detection tool.
