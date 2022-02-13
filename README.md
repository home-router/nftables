# Ansible role for nftables firewall

This is an ansible role to configure nftables firewall.

[`defaults/main.yml`](./defaults/main.yml) provides a usable firewall configuration 
which is inspired by firewall rules on EdgeRouter and VyOS.

The example rules show following features:

- NAT
  - masquerade on pppoe interface
  - source and destination NAT
    - port forwarding from WAN to interal is accomplished with destination NAT
- Blocking all traffic on WAN (pppoe) interface
  - Allowing ICMPv6 for IPv6 to work
- Opening ports for specific services

Writing firewall rules are not easy. This project is more of a project to learn
nftables instead of replacing other high level firewall tools. But for home router
usage, I think the rules should be enough to get started.

## Filter plugin

The [filter_plugins/nftables.py](./filter_plugins/nftables.py) accepts rule definition in dict and generates nftables rules.

Rule definition structure follows nftables rule:

```yaml
# Use raw key to write nftable rule directly.
#raw: 
match:
  target1:
    key: v
  target2:
    key: v
action:
  act_name:
    key: v
```

The rule generation code is divided into following main component:

- `MatchGenerator`
- `ActionGenerator`
- `RuleGenerator`
  - Which relies on the above two generators to generate final nftables rule.

The filter allows user to write nftables rules directly using the `raw` key in rule dict.

## nftables reference

### rule structure

nftables rule follow the following structure:

```
match [match2...] action
```

It's possible to have multiple actions:

```
{ tcp : jump tcp-chain, udp : jump udp-chain, icmp : jump icmp-chain }
```

I'm not supporting this feature for now. Use `raw` key in rule if this feature is needed.

#### References

- [nft.8](https://man.archlinux.org/man/nft.8) manpage on Arch Linux website
  - [IPv4 header expression](https://man.archlinux.org/man/nft.8#IPV4_HEADER_EXPRESSION)
  - [TCP header expression](https://man.archlinux.org/man/nft.8#TCP_HEADER_EXPRESSION)
  - [Statements](https://man.archlinux.org/man/nft.8#STATEMENTS)

### Tables

5 different **families** of tables for now:

- `ip`
- `ip6`
- `inet` (kernel 3.14 and up)
  - mixed ipv4/ipv6 chains
  - ues `meta nfproto ipv4/ipv6` to limit to only one protocol
- `arp`
- `bridge`
- `netdev`
  - filter early in the stack (kernel 4.2 and up).

### Chains

nftables does not have predefined chains. We have to define by our own.

Two kinds of chains:

- **base chain**
  - has a **hook** registered with **type** and **priority**
  - can specify default **policy** for packets not explicitly accepted (default) or refused in all contained rules
- **non-base chain**

Chain **types**:

- `filter`
  - 用来决定包是否能通过
- `route`
  - 用来重路由包
- `nat`
  - 用于执行地址转换 (Networking Address Translation (NAT))，改写包的 src/dst, ip/port
  - only the first packet of a flow hits this chain, can't be used for filtering
  
**Hooks**:

- `prerouting`
  - before the routing decision, all packets entering the machine hit this hook
- `input`
  - packets for the local system hit this hook
- `forward`
  - packets not for the local system, those that need to be forwarded hit this hook
- `output`
  - packets that originate from the local system hit this hook
- `postrouting`
  - comes after the routing decision has been made, all packets leaving the machine hit this hook
  
For priority, the lower value means higher priority. Negative values are allowed.

Standard priority names and values:

| Name    | Value| Families       | Hooks |
|---------|------|----------------|-------|
| raw     | -300 | ip, ip6, inet  | all   |
| mangle  | -150 | ip, ip6, inet  | all   |
| dstnat  | -100 | ip, ip6, inet  |prerouting|
| filter  |    0 | ip, ip6, inet, arp, netdev| all |
| security|   50 | ip, ip6, inet  | all   |
| srcnat  |  100 | ip, ip6, inet  |postrouting|

For the bridge family:

|Name   | Value | Hooks     |
|-------|-------|-----------|
|dstnat | -300  |prerouting |
|filter | -200  |all        |
|out    |  100  |output     |
|srcnat |  300  |postrouting|

We can write arithmetic expression like `mangle - 5` to define priority.

![Packet Flow in Netfilter](docs/netfilter-packet-flow.svg)
The packet flow picture comes from [Wikipedia](https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg).
Use this picture to help understand hooks location.

Example:

```
chain INPUT {
    # This is a base chain.
    type filter hook input priority filter; policy accept;
    counter jump FIREWALL_LOCAL_HOOK
}

chain FIREWALL_LOCAL_HOOK {
    # This is a non-base chain.
    iifname "pppoe0" drop
}
```

### Usage of different predefined tables in iptables

|Tables↓/Chains→               |PREROUTING|INPUT|FORWARD|OUTPUT|POSTROUTING|
|------------------------------|----------|-----|-------|------|-----------|
|(routing decision)            |          |     |       |   ✓  |           |
|raw                           |    ✓     |     |       |   ✓  |           |
|(connection tracking enabled) |    ✓     |     |       |   ✓  |           |
|mangle                        |    ✓     |  ✓  |   ✓   |   ✓  |     ✓     |
|nat (DNAT)                    |    ✓     |     |       |   ✓  |           |
|(routing decision)            |    ✓     |     |       |   ✓  |           |
|filter                        |          |  ✓  |   ✓   |   ✓  |           |
|security                      |          |  ✓  |   ✓   |   ✓  |           |
|nat (SNAT)                    |          |  ✓  |       |      |     ✓     |

The above picture is a reference of iptables predefined chains.

- `filter`
  - decide whether a packet can continer to its destination or not
- `nat`
  - do network address translation
- `mangle`
  - change packet IP headers (e.g. Time to live), place internal kernel mark (not touching the actual packet)
- `raw`
  - provide a mechanism for marking packets in order to opt-out of connection tracking
- `security`
  - set internal SELinux security context marks on packets

We follow the name of these chains when creating nftables chains.

#### `jump` vs. `goto`

From [Jumping to chain](https://wiki.nftables.org/wiki-nftables/index.php/Jumping_to_chain).

- `jump`
  - packet will **return to the chain** of the calling rule after the end
- `goto`
  - packets will **NOT return to the chain** of the calling rule
  - default policy of the base chain will be applied after the end of the goto chain
  
The `nftables.conf.j2` template uses goto when all the conditions are met:

- it's a base chain, or it's the only chain called in a base chain
- all rules in the chain matches on interfaces (`oifname`, `iifname`, etc.)

#### References

- [Nftables](https://wiki.gentoo.org/wiki/Nftables) from Gentoo Wiki
- [A Deep Dive into Iptables and Netfilter Architecture](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture)
  [[译] 深入理解 iptables 和 netfilter 架构](http://arthurchiao.art/blog/deep-dive-into-iptables-and-netfilter-arch-zh/)
  - **Highly recommended to read.** Detailed and easy to follow analysis for packet flow
  - I'm coping many parts of this article which I think is most useful for daily use in this doc

### conntrack

Meaning of each state:

- **New**
  - packet is not part of any known flow
  - for TCP packets, flags have the **SYN bit on**
- **Established**
  - packet matches a flow tracked by CONNTRACK 
  - for TCP packets, SYN bit must be off for a packet to be in state established
- **Related**
  - packet does not match any known flow, but is expected because of existing connection
  - examples:
    - FTP session on port 21 followed by data transfer on port 20
    - UDP data for an existing SIP connection on TCP port 5060
- **Invalid**
  - invalid header, checksum, TCP flags, ICMP messages, out of sequence packets
  - running out of CONNTRACK entries (check `dmesg`)

#### Is drop invalid state rule necessary?

If you have reject rules, then yes. I learned the answer comes from this [Server Fault answert](https://serverfault.com/a/1031084/94892).
Also refer to this [man page section](https://man.archlinux.org/man/iptables-extensions.8.en#REJECT_(IPv4-specific)).

Coping the related content from man page:

> Warning: You should not indiscriminately apply the REJECT target to packets whose connection state is classified as INVALID; instead, you should only DROP these.
>
> Consider a source host transmitting a packet P, with P experiencing so much delay along its path that the source host issues a retransmission, P_2, with P_2 being successful in reaching its destination and advancing the connection state normally. It is conceivable that the late-arriving P may be considered not to be associated with any connection tracking entry. Generating a reject response for a packet so classed would then terminate the healthy connection.
>
> So, instead of:
>
>     -A INPUT ... -j REJECT
> do consider using:
>
>     -A INPUT ... -m conntrack --ctstate INVALID -j DROP -A INPUT ... -j REJECT

#### References

- [Connection Tracking (conntrack): Design and Implementation Inside Linux Kernel](http://arthurchiao.art/blog/conntrack-design-and-implementation/)
  - Introduction to conntrack and kernel implementation
- [Conntrack tales - one thousand and one flows](https://blog.cloudflare.com/conntrack-tales-one-thousand-and-one-flows/)
  - this CloudFlare blog article shows how to test part of conntrack with "unshare"
- [Simple stateful firewall](https://wiki.archlinux.org/index.php?title=Simple_stateful_firewall)

## NAT

### Port-forwarding

Also called **destination NAT** because this is how it's implemented with nftables.

### Hairpinning (or NAT loopback)

[Wikipedia](https://en.wikipedia.org/wiki/Hairpinning) has an example of the use scenario
of hairpinning.

TODO

### Full-cone NAT etc.

Different types of NAT implementation:

- Full-cone NAT
- Symmetric NAT
- Restricted cone or restricted port cone NAT

TODO

# MSS clamping

Refer to this [TLDP doc](https://tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.cookbook.mtu-mss.html) for what is MSS clamping.
