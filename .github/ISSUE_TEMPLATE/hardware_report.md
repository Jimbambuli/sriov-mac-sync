---
name: Hardware report
about: How your NIC behaved - the one thing this project still collects
title: 'hardware: '
labels: hardware
assignees: ''

---

**NIC and driver** (`ethtool -i <uplink>`):

**The four steps from the README**, and what each printed:

```
bridge fdb add 02:00:00:00:00:99 dev <uplink-vf> self permanent
bridge fdb show dev <uplink-vf> self
# ...does a peer behind the bridge reach a guest now?
bridge fdb del 02:00:00:00:00:99 dev <uplink-vf> self permanent
```

**What `sriov-mac-sync --check` said:**

**Anything the driver did that surprised you:**
