# openSUSE MicroOS Setup Script (Root Version)

A simple, comprehensive post-installation script designed to run as root on openSUSE MicroOS.

## 🎯 **Designed for Root**

- ✅ **No sudo calls** - Runs all commands directly as root
- ✅ **No user validation hassles** - Just run as root
- ✅ **Full system access** - Can modify anything needed
- ✅ **Simple and direct** - No complex permission handling

## 🚀 **Usage**

### **Production (openSUSE MicroOS as root)**
```bash
# Make executable
chmod +x microos-root-setup.sh

# Run as root
./microos-root-setup.sh

# Or with sudo
sudo ./microos-root-setup.sh
```

### **Testing (any system)**
```bash
# Complete test mode (simulates everything)
TEST_MODE=true FORCE_RUN=true ./microos-root-setup.sh

# Test on non-MicroOS system
FORCE_RUN=true ./microos-root-setup.sh
```

## 📋 **Menu Options**

1. **Update System** - Updates all packages
2. **Install Essential Packages** - Basic tools and utilities
3. **Install Development Tools** - Docker, Python, Node.js, build tools
4. **Install Network Tools** - SSH, firewall, network utilities
5. **Setup Firewall** - Configures firewalld with common ports
6. **Setup SSH** - Enables SSH with security improvements
7. **Optimize System** - Memory and network optimizations
8. **Setup User Environment** - Useful aliases for all users
9. **Install Everything (Full Setup)** - Does all of the above
10. **Show Log** - View installation log
11. **Exit** - Shows summary and exits

## 🔧 **What Gets Installed**

### **Essential Packages (Option 2)**
- `curl`, `wget` - Download tools
- `git` - Version control
- `vim`, `nano` - Text editors
- `htop` - System monitor
- `zip`, `unzip` - Archive tools
- `rsync`, `tree` - File utilities

### **Development Tools (Option 3)**
- `docker`, `podman` - Container platforms
- `python3`, `python3-pip` - Python development
- `nodejs`, `npm` - Node.js development
- `gcc`, `make`, `cmake` - Build tools
- `git-core` - Git development tools

### **Network Tools (Option 4)**
- `openssh-server` - SSH server
- `firewalld` - Firewall service
- `net-tools` - Network utilities
- `nmap` - Network scanning
- `tcpdump`, `wireshark` - Packet analysis

## ⚙️ **System Configuration**

### **Firewall Setup (Option 5)**
- Enables firewalld service
- Opens SSH (22/tcp)
- Opens HTTP (80/tcp)
- Opens HTTPS (443/tcp)
- Opens development port (8080/tcp)

### **SSH Security (Option 6)**
- Enables SSH service
- Disables root login via SSH
- Enables password authentication
- Creates backup of SSH config

### **System Optimization (Option 7)**
- Reduces swappiness to 10 (better for SSD)
- Sets dirty ratio to 5 (better performance)
- Optimizes network buffer sizes
- Applies settings immediately

### **User Environment (Option 8)**
- Creates system-wide aliases in `/etc/profile.d/`
- Adds useful shortcuts for all users
- Includes Docker, Git, and system aliases

## 🎯 **Key Advantages**

1. **Root-native** - Designed from ground up for root execution
2. **No permission issues** - Direct system access
3. **Comprehensive** - 26 packages + full system configuration
4. **MicroOS-aware** - Handles both Desktop and Server variants
5. **Test mode** - Safe testing without changes
6. **Logging** - All actions logged to `/var/log/microos-setup.log`

## 🔍 **Variant Detection**

### **Desktop Variant**
- Uses `pkcon` for package management
- Immediate installation (no reboot needed)

### **Server Variant**
- Uses `transactional-update` for packages
- Requires reboot after installation
- Script offers automatic reboot option

## 📊 **Full Setup Example**

Option 9 performs the complete installation:
```
✅ System update
✅ 26 packages installed
✅ Firewall configured
✅ SSH secured and enabled
✅ System optimized
✅ User environment configured
✅ Docker service enabled
```

## 🔧 **Advanced Usage**

### **Environment Variables**
```bash
FORCE_RUN=true    # Run on non-MicroOS systems
TEST_MODE=true    # Simulate all operations
```

### **Log Locations**
- **As root**: `/var/log/microos-setup.log`
- **As user**: `$HOME/microos-setup.log`

### **Package Variants**
The script automatically detects and uses:
- **pkcon** (Desktop variant)
- **transactional-update** (Server variant)

## 🎉 **Perfect For**

- Fresh openSUSE MicroOS installations
- Server deployments
- Development environment setup
- System administrators who prefer root access
- Automated deployment scripts

---

**Simple, powerful, and designed for root! 🔑**