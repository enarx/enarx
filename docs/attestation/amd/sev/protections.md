# Protections

An SEV-enabled guest will be protected from a number of potential threats.

These threats are broadly categorized like so:

**Confidentiality**: Anything that could disclose and/or read the contents of the virtual machine without
its explicit permission is a threat to the virtual machine's confidentiality.

**Integrity**: The virtual machine must always see the data that it last wrote. If this invariant is broken,
then the integrity of the virtual machine is compromised.

**Physical Access Attacks**: An attacker with a substantial level of access to the physical hardware may use
this access to conduct attacks on the system and virtual machines running on it.

**Miscellaneous**: An attack which doesn't fit in as nicely to any of the other above categories.

Table legend:

* :heavy\_check\_mark:: indicates that this attack is thwarted by an SEV feature.

* :star2:: indicates that this mitigation may be optionally enabled.

* : an empty cell indicates that the attack is *not* mitigated by that technology.

| **Confidentiality** | **SEV** | **SEV-ES** | **SEV-SNP** |
| ------------------: | :-----: | :--------: | :---------: |
| VM Memory (*ex: Hypervisor reads private VM memory*) | :heavy\_check\_mark: | :heavy\_check\_mark: | :heavy\_check\_mark: |
| VM Register State (*ex: Hypervisor attempts to read VM register context*) | | :heavy\_check\_mark: | :heavy\_check\_mark: |
| DMA Protection (*ex: Device attempts to read VM memory*) | :heavy\_check\_mark: | :heavy\_check\_mark: | :heavy\_check\_mark: |
| **Integrity** | **SEV** | **SEV-ES** | **SEV-SNP** |
| Replay Protection (*ex: VM memory is replaced with an old copy*) | | | :heavy\_check\_mark: |
| Data Corruption (*ex: VM memory is replaced with junk data*) | | | :heavy\_check\_mark: |
| Memory Aliasing (*ex: Hypervisor maps two guest pages to same DRAM page*) | | | :heavy\_check\_mark: |
| Memory Re-mapping (*ex: Hypervisor switches DRAM page mapped to a guest page*) | | | :heavy\_check\_mark: |
| **Availability** | **SEV** | **SEV-ES** | **SEV-SNP** |
| Guest to Host Denial of Service (*ex: Guest refuses to yield/exit*) | :heavy\_check\_mark: | :heavy\_check\_mark: | :heavy\_check\_mark: |
| Host to Guest Denial of Service (*ex: Host refuses to run guest*) | | | |
| **Physical Access Attacks** | **SEV** | **SEV-ES** | **SEV-SNP** |
| Offline DRAM analysis (*ex: Cold boot*) | :heavy\_check\_mark: | :heavy\_check\_mark: | :heavy\_check\_mark: |
| Active DRAM corruption (*ex: Manipulate DDR bus while VM is running*) | | | |
| **Miscellaneous Attacks** | **SEV** | **SEV-ES** | **SEV-SNP** |
| TCB Rollback (*ex: AMD-SP firmware is reverted to older version*) | | | :heavy\_check\_mark: |
| Malicious Interrupt/Exception Injection (*ex: interrupt injected while RFLAGS.IF=0*) | | | :star2: |
| Indirect Branch Predictor Poisoning (*ex: Poison BTB from hypervisor*) | | | :star2: |
| Secure Hardware Debug Registers (*ex: Breakpoints changed during debugging*) | | | :star2: |
| Trusted CPUID Information (*ex: Hypervisor lies about platform capabilities*) | | | :star2: |
| Architectural Side Channels (*ex: PRIME+PROBE to track VM accesses*) | | | |
| Page-level Side Channels (*ex: Track VM access patterns through page tables*) | | | |
| Performance Counter Tracking (*ex: Fingerprint VM workloads by performance data*) | | | |

*The table above was taken directly from the [AMD SEV-SNP Whitepaper (Table 1: Threat Model)](
https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf).*
