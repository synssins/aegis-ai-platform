# Resizable BAR (ReBAR) for GPUs that need it — host, VM, or bare metal

Some accelerators — notably Intel Arc (Alchemist/Battlemage) and many datacentre cards — expose their whole
VRAM only when the PCIe Base Address Register can be resized above the legacy 256 MB window. Without it the
driver falls back to slow paths or refuses to initialise. This page is **hardware-agnostic**: replace the PCI
addresses and sizes with yours. It covers three layouts:

- **Bare metal** (Linux runs directly on the machine): steps 1–3.
- **Hypervisor host + VM** (e.g. Proxmox/QEMU with PCI passthrough): steps 1–3 on the host, then step 4 in the VM config, step 5 in the guest.
- **Firmware lacks ReBAR entirely**: step 1b.

## 1. Firmware
Enable, in this order, in the system firmware: **Above 4G Decoding**, **Resizable BAR** (a.k.a. Smart Access
Memory / SR-IOV-adjacent "large BAR" options), and — for passthrough hosts — **IOMMU / VT-d / AMD-Vi**. Disable
CSM (legacy boot); ReBAR requires UEFI.

### 1b. Firmware that has no ReBAR option
The **ReBarUEFI** project injects a DXE driver into the firmware image that advertises ReBAR support on boards
whose vendors never exposed it: <https://github.com/xCuri0/ReBarUEFI>. Read its compatibility notes; flashing
firmware carries brick risk, and Above 4G Decoding must still be available. Alternative for Linux hosts: skip
firmware support and rely on step 2 — the kernel can resize BARs itself on most platforms once Above 4G is on.

## 2. Linux host (or bare metal): resize the BAR from the kernel
Linux ≥ 5.15 exposes per-BAR resize controls in sysfs. Find the device and its supported sizes:
```
lspci -nn | grep -iE 'vga|3d|display'                 # e.g. 03:00.0
lspci -vvs 03:00.0 | grep -A4 'Resizable BAR'         # shows BAR index and supported sizes
ls /sys/bus/pci/devices/0000:03:00.0/ | grep resize   # resource0_resize, resource2_resize, ...
cat /sys/bus/pci/devices/0000:03:00.0/resource2_resize # bitmask of supported sizes
```
Sizes are powers of two: value `n` = 2^n MB (8 = 256 MB, 13 = 8 GB, 15 = 32 GB). The device must be **unbound
from its driver** while resizing, and the resize must happen **before** a VFIO or GPU driver claims it:
```
echo 0000:03:00.0 > /sys/bus/pci/devices/0000:03:00.0/driver/unbind   # if bound
echo 15 > /sys/bus/pci/devices/0000:03:00.0/resource2_resize           # 32 GB BAR
echo 1  > /sys/bus/pci/devices/0000:03:00.0/remove && echo 1 > /sys/bus/pci/rescan   # re-enumerate
```
Kernel command line that helps on picky platforms: `pci=realloc` (let the kernel move windows to make room).

### 2b. Make it automatic at boot
A oneshot unit that runs before the VFIO/GPU drivers bind. Replace addresses, BAR index and size:
```ini
# /etc/systemd/system/gpu-rebar.service
[Unit]
Description=Resize GPU BARs before drivers bind
DefaultDependencies=no
After=sysinit.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gpu-rebar.sh

[Install]
WantedBy=basic.target
```
```sh
#!/bin/sh
# /usr/local/sbin/gpu-rebar.sh — hardware-agnostic: list "<pci-address> <bar-index> <size-exponent>" lines
set -e
while read -r dev bar exp; do
  [ -z "$dev" ] && continue
  d=/sys/bus/pci/devices/$dev
  [ -e "$d/driver" ] && echo "$dev" > "$d/driver/unbind"
  echo "$exp" > "$d/resource${bar}_resize"
done <<EOF
0000:03:00.0 2 15
0000:04:00.0 2 15
EOF
echo 1 > /sys/bus/pci/rescan
```
Enable: `systemctl enable gpu-rebar`. If the GPU driver loads too early, add it to `/etc/modprobe.d/` with
`softdep` ordering or blacklist it on a passthrough host (VFIO hosts bind `vfio-pci` instead).

## 3. Verify on the host
`lspci -vvs 03:00.0 | grep -E 'Region|Resizable'` — the region size should now read the new value (e.g.
`[size=32G]`). `dmesg | grep -i bar` shows resize messages or reasons for refusal (usually "no space" →
enable Above 4G / add `pci=realloc`).

## 4. Hypervisor VM configuration (QEMU/Proxmox)
The guest needs a **64-bit MMIO window large enough for all resized BARs** plus headroom, and a modern machine type:
- Machine `q35`, firmware **OVMF (UEFI)**, `pcie=1` on the passthrough entries.
- Large MMIO window for OVMF: on Proxmox add to the VM config
  `args: -fw_cfg opt/ovmf/X-PciMmio64Mb=<MB>` — e.g. `131072` (128 GB) for two 32 GB BARs with margin.
- Some setups also need `-global q35-pcihost.pci-hole64-size=<size>G`.
- Pass through the whole device (all functions) and keep the host's resized BAR — the guest sees it as-is.

## 5. Guest (VM) kernel
Usually nothing. If the guest logs BAR allocation failures: add `pci=realloc` to the guest kernel command line,
confirm the guest firmware is UEFI, and check `lspci -vv` inside the guest for `[size=32G]`.

## 6. Container access (this platform)
GPUs reach containers through CDI (`docs/OPERATIONS.md` → GPUs). No BAR configuration is needed inside
containers; they see whatever the guest kernel enumerated.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| `write error: No space left on device` when resizing | Above 4G decoding off, or the bridge window is too small → `pci=realloc`, check firmware |
| Resize accepted but size unchanged after rescan | driver rebound before rescan; run with the driver unbound/blacklisted |
| Guest sees 256 MB BAR | MMIO window too small in the VM (`X-PciMmio64Mb`), or not q35/OVMF |
| Firmware has no ReBAR toggle | try step 2 anyway (kernel-driven); otherwise ReBarUEFI |

References: Linux PCI sysfs ABI (`Documentation/ABI/testing/sysfs-bus-pci`, `resourceN_resize`); ReBarUEFI
<https://github.com/xCuri0/ReBarUEFI>; OVMF `X-PciMmio64Mb` fw_cfg option (EDK2 OvmfPkg).


---

## Worked example: Proxmox VE host + Ubuntu guest, host without native ReBAR (Dell PowerEdge R740, NVIDIA Tesla T4 + Intel Arc B60)

This is the configuration this platform was first built on, preserved from the original documentation. Replace PCI addresses, vendor IDs and sizes with yours; the generic procedure above explains each step.

Hardware-specific configuration guide for Proxmox VE hypervisors deploying multi-GPU passthrough (e.g., NVIDIA Tesla T4 and Intel Arc B60/Alchemist) on enterprise hosts lacking native Resizable BAR (such as Dell PowerEdge R740).

### 1. Proxmox Host Configuration (Bare Metal)

#### Enable IOMMU and PCI Reallocation
Edit `/etc/default/grub` to append vendor-specific IOMMU flags and PCI reallocation parameters to `GRUB_CMDLINE_LINUX_DEFAULT`:
- **Intel CPUs:** `intel_iommu=on iommu=pt pci=realloc`
- **AMD CPUs:** `amd_iommu=on iommu=pt pci=realloc`

Update GRUB bootloader:
```bash
update-grub
```

#### Configure VFIO Driver Binding & Blacklisting
Identify target GPU PCI IDs (Intel `8086`, NVIDIA `10de`, AMD `1002`):
```bash
lspci -nn | grep -iE 'vga|3d|audio' | grep -oP '\[\K[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(?=\])' | sort -u | paste -sd, -
```

Create `/etc/modprobe.d/vfio.conf` to bind device IDs to `vfio-pci` with soft dependency ordering:
```ini
options vfio-pci ids=<TARGET_GPU_IDS> disable_idle_d3=1 disable_vga=1
softdep xe pre: vfio-pci
softdep i915 pre: vfio-pci
softdep amdgpu pre: vfio-pci
softdep radeon pre: vfio-pci
softdep snd_hda_intel pre: vfio-pci
```

Create `/etc/modprobe.d/blacklist-gpus.conf` to prevent the host kernel from attaching native graphics drivers:
```ini
blacklist xe
blacklist i915
blacklist amdgpu
blacklist radeon
blacklist snd_hda_intel
blacklist snd_soc_avs
options xe modeset=0
options i915 modeset=0
options amdgpu modeset=0
options radeon modeset=0
```

#### Enforce Early VFIO Module Loading & Initramfs Rebuild
Add VFIO modules to `/etc/modules`:
```text
vfio
vfio_iommu_type1
vfio_pci
```

Rebuild the initramfs:
```bash
update-initramfs -u -k all
```

---

### 2. Physical Resizable BAR (ReBAR) Automation Service

On hosts without native UEFI ReBAR support, blacklisting the native `xe` driver causes Intel Arc cards to default to a 256MB BAR limit. To enable full VRAM addressing before VMs initialize, deploy a systemd oneshot service (`/etc/systemd/system/arc-rebar.service`) that unbinds each card, requests a 32GB BAR resize (`echo 15`), and rebinds to `vfio-pci`:

```ini
[Unit]
Description=Resize Intel Arc ReBAR for VFIO
Before=pve-guests.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c '\
  for dev in $(lspci -Dnn | grep -iE "vga|3d" | grep -i "8086" | awk "{print \\$1}"); do \
    echo $dev > /sys/bus/pci/drivers/vfio-pci/unbind; \
    echo 15 > /sys/bus/pci/devices/$dev/resource2_resize; \
    echo $dev > /sys/bus/pci/drivers/vfio-pci/bind; \
  done'

[Install]
WantedBy=multi-user.target
```

Enable the service:
```bash
systemctl enable arc-rebar.service
```

---

### 3. Proxmox Virtual Machine Configuration

Modify the guest VM definition in `/etc/pve/qemu-server/<VMID>.conf`:
- **Machine & BIOS:** Set machine to `q35` and BIOS to `OVMF (UEFI)`.
- **64-bit MMIO Window:** Allocate a 2048GB MMIO hole to accommodate enlarged BAR allocations:
  ```text
  args: -global q35-pcihost.pci-hole64-size=2048G
  ```
- **PCIe Topologies:** Configure the passthrough hardware with PCIe addressing and disable VGA emulation. For Intel Arc cards requiring guest ReBAR, enforce `rombar=1` and `x-vga=0`:
  ```text
  hostpci0: <gpu1-pci-address>,pcie=1
  hostpci1: <gpu2-pci-address>,pcie=1,x-vga=0,rombar=1
  ```

---

### 4. Guest VM Setup & Validation (Ubuntu)

Inside the guest operating system:

1. **Install drivers and guest agent:**
   ```bash
   sudo apt update
   sudo apt install -y qemu-guest-agent nvidia-driver-550
   sudo apt install -y --reinstall linux-firmware
   sudo systemctl enable --now qemu-guest-agent
   ```

2. **Reboot Guest:**
   A full reboot is mandatory for OVMF BIOS to negotiate the 32GB ReBAR windows with the expanded host hardware (do not rely on live sysfs rescans):
   ```bash
   sudo reboot
   ```

3. **Validate Memory Expansion:**
   Verify the prefetchable memory region expanded from 256MB to 32GB on the Arc GPU:
   ```bash
   sudo lspci -vvv -d 8086:e211 | grep -iE 'Region.*Memory.*size'
   ```

4. **Verify Driver Initialization & VRAM:**
   Confirm Intel `xe` VRAM allocation and NVIDIA T4 visibility:
   ```bash
   sudo dmesg | grep -iE 'xe.*vram'
   nvidia-smi
   ```

