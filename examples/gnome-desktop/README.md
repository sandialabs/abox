# GNOME Desktop Example

An abox instance running a full GNOME desktop session accessible via RDP (Remote Desktop Protocol).

## Prerequisites

You need an RDP client installed on your host machine:

- **Linux**: Remmina (`sudo apt install remmina remmina-plugin-rdp`)
- **macOS**: Microsoft Remote Desktop (from App Store)
- **Windows**: Built-in Remote Desktop Connection (mstsc.exe)

## Setup

```bash
cd examples/gnome-desktop
abox up
```

This takes approximately 5-10 minutes as it downloads and installs the GNOME desktop environment.

After provisioning completes, forward the RDP port:

```bash
abox forward add gnome-desktop 3389:3389
```

## Connect

Open your RDP client and connect to:

- **Host**: `localhost:3389`
- **Username**: `ubuntu`
- **Password**: `ubuntu`

### Linux (Remmina)

1. Open Remmina
2. Click the "+" button to create a new connection
3. Set Protocol to "RDP"
4. Set Server to `localhost:3389`
5. Set Username to `ubuntu` and Password to `ubuntu`
6. Click "Save and Connect"

### macOS (Microsoft Remote Desktop)

1. Open Microsoft Remote Desktop
2. Click "Add PC"
3. Set PC name to `localhost:3389`
4. Click "Add"
5. Double-click to connect, enter `ubuntu` / `ubuntu` when prompted

### Windows

1. Press Win+R, type `mstsc`, press Enter
2. Enter `localhost:3389` as the computer
3. Click "Connect"
4. Enter `ubuntu` / `ubuntu` when prompted

## Security Note

The default password is `ubuntu`. To change it after connecting:

```bash
passwd
```

## Network Filtering

This instance has DNS/HTTP filtering enabled. Only Ubuntu package repositories are allowlisted by default. To add more domains:

```bash
abox allowlist add gnome-desktop example.com
```

To verify filtering is working, open a terminal in GNOME and try:

```bash
# This should fail (not allowlisted)
curl https://example.com

# This should work (allowlisted)
curl https://archive.ubuntu.com
```

## Troubleshooting

### Black screen after connecting

Wait a few seconds - GNOME may take time to initialize on first login. If it persists, try disconnecting and reconnecting.

### "Authentication required" dialogs

The polkit rules should prevent most of these. If you see them, you can usually click "Cancel" safely.

### Connection refused

1. Check the VM is running: `abox status gnome-desktop`
2. Check the port forward is active: `abox forward list gnome-desktop`
3. Check xrdp is running inside the VM:
   ```bash
   abox ssh gnome-desktop -- sudo systemctl status xrdp
   ```

### Slow performance

GNOME is resource-intensive. You can increase resources by editing `abox.yaml` and recreating the instance:

```bash
abox down --remove
# Edit abox.yaml to increase cpus/memory
abox up
```

## Customization

### Alternative Desktop Environments

For a lighter-weight desktop, modify `provision.sh` to install a different DE:

**XFCE** (lighter):
```bash
apt-get install -y xfce4 xfce4-goodies xrdp dbus-x11
# Change startwm.sh to: exec startxfce4
```

**KDE Plasma**:
```bash
apt-get install -y kde-plasma-desktop xrdp dbus-x11
# Change startwm.sh to: exec startplasma-x11
```

### Persistent Sessions

By default, each RDP connection starts a new session. The session persists while connected but ends on disconnect.

## Cleanup

```bash
abox down --remove
```
