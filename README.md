# vuln-boilerplate

simple windows kernel exploitation boilerplate using a vulnerable driver for physical memory r/w.

the driver side is meant to be swapped out. just add your own provider with `read_phys` and `write_phys`, then pass the callbacks into `vdm::memory`. lenovo ( CVE-2022-3699 ) is only the example provider here.

the rest handles virtual memory, kernel symbols / offsets, grabbing the system token, and spawning a system cmd.

made for research / learning. dont be stupid with it.
