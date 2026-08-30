---
name: Bug report
about: Something the daemon did, or failed to do
title: ''
labels: bug
assignees: ''

---

**What happened, and what should have happened instead**

**The setup**
- NIC and driver (`ethtool -i <uplink>`):
- How the uplink sits in the bridge (`--status` output helps):
- Distribution and kernel (`uname -r`):
- Version (`sriov-mac-sync --version`) and how it was installed (.deb/.ipk/.apk/cargo):

**What the daemon said**
`journalctl -u sriov-mac-sync` around the time it happened - the trigger
suffixes (`[timed]`, `[reflection]`, `[quiet]`, ...) are usually the story.

**If reachability is the symptom**
The four `bridge fdb` steps under VERIFYING in `man sriov-mac-sync` tell
apart "the kernel took it" from "the card acts on it" - their output places
the problem.
