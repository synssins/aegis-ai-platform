# Aegis AI Platform

A universally deployable, cryptographically siloed AI inference platform designed for bare-metal hypervisors. 

## Architecture
* **Compute:** Hardware-agnostic GPU passthrough (PCIe VFIO) with automated ReBAR support (specifically for Intel GPUs installed on hardware that does not support ReBAR, such as the Dell PowerEdge R740).
* **Virtualization:** Proxmox bare-metal host running an isolated Linux guest.
* **Networking:** Completely isolated Docker bridge (`ai-secure-net`) hidden behind a Caddy reverse proxy handling internal TLS. No internal container ports are bound to the host.

## Security Guardrails
* **The Veto Proxy:** A custom LiteLLM pre-call interceptor (`veto_filter.py`) utilizing zero-tolerance regex strict-matching. It instantly severs any inference requests attempting to generate malware, reverse shells, or illegal explicit material before they reach the routing logic.
* **Air-gapped Ports:** All internal ingress is strictly funneled through encrypted HTTPS gateways. 

## Inference Stack
* **Engine:** Ollama managing hot-swappable GGUF models, dynamic VRAM allocation, and system RAM offloading for massive context windows.
* **Gateway:** LiteLLM handling OpenAI-compliant translation and unified API routing.
* **Interface:** OpenWebUI providing a centralized frontend for chat, document vectorization, and localized token-per-second benchmarking.

## Bare-Metal VFIO & ReBAR Passthrough Configuration

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
  hostpci0: 0000:3b:00,pcie=1
  hostpci1: 0000:3d:00,pcie=1,x-vga=0,rombar=1
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

