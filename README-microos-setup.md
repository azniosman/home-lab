# openSUSE MicroOS Post-Installation Setup Script

A comprehensive, menu-driven post-installation script for openSUSE MicroOS that automatically configures your system with essential packages, development tools, and security settings.

## ✅ **FIXED: User Detection Issue**

The script now properly validates users across different systems:
- ✅ **macOS (UID 501)**: Works in test mode
- ✅ **Linux (UID 1000)**: Works in production mode  
- ✅ **Any non-root user**: Properly detected and validated
- ❌ **Root (UID 0)**: Correctly rejected for security

## 🚀 **Usage Options**

### **Production Deployment (openSUSE MicroOS)**
```bash
# Standard interactive installation
./microos-post-install.sh

# Quick automated installation
./microos-post-install.sh --auto
```

### **Testing & Development**
```bash
# Test mode (skips OS/sudo validation)
./microos-post-install.sh --test

# Debug mode with detailed user info
./microos-post-install.sh --debug

# No validation (development only)
./microos-post-install.sh --no-validation

# Skip sudo validation entirely
SKIP_SUDO=true ./microos-post-install.sh
```

### **Help & Information**
```bash
# Show help
./microos-post-install.sh --help

# Show current user status
./microos-post-install.sh --debug
```

## 🎯 **Menu Options**

1. **Run Pre-Installation Checks** - Comprehensive system validation
2. **Quick Setup** - One-click full installation  
3. **Custom Installation Menu** - Select specific components
4. **System Information & Status** - Detailed system overview
5. **View Installation Log** - Color-coded log viewer
6. **Help & Documentation** - Built-in help system

## 🔧 **What Gets Installed**

### **Essential Tools**
- System utilities: `curl`, `wget`, `git`, `vim`, `htop`, `btop`
- Archive tools: `zip`, `unzip`, `tar`
- Network tools: `NetworkManager-applet`, `openssh-server`

### **Development Environment**
- Containers: `docker`, `podman`, `docker-compose`
- Languages: `python3`, `nodejs`, `npm`
- Build tools: `gcc`, `make`, `cmake`, `build-essential`
- Version control: `git`, `gh` (GitHub CLI)
- Editors: `code` (VS Code), `vim`

### **Security & System**
- Firewall: `firewalld` with sensible defaults
- SSH: Server setup with key generation
- System optimizations: Memory, network tuning
- User environment: Aliases, shell improvements

## 🛡️ **Security Features**

- **Never runs as root** - Validates user is not UID 0
- **Sudo validation** - Requests privileges only when needed
- **Sudo keepalive** - Maintains privileges during installation
- **Firewall configuration** - Secure defaults with development ports
- **SSH key generation** - Automatic key pair creation
- **System optimizations** - Performance and security tuning

## 📋 **System Requirements**

- **OS**: openSUSE MicroOS (Desktop or Server variant)
- **User**: Regular user account (not root)
- **Privileges**: Sudo access required
- **Network**: Internet connection recommended
- **Storage**: Minimum 2GB free disk space

## 🐛 **Troubleshooting**

### **"This script should not be run as root" Error**
```bash
# Check your current user
whoami && id -u

# If showing UID 0, switch to regular user
su - username
./microos-post-install.sh
```

### **"Sudo access required" Error**
```bash
# Test sudo access
sudo -v

# Add user to sudo group (if needed)
sudo usermod -aG wheel username
```

### **Testing on Non-MicroOS Systems**
```bash
# Use test mode
./microos-post-install.sh --test

# Or debug mode
DEBUG_MODE=true ./microos-post-install.sh
```

## 📊 **Installation Summary**

After completion, the script generates:
- **Summary file**: `~/microos-setup-summary.txt`
- **Log file**: `/var/log/microos-post-install.log` (or fallback location)
- **Package list**: All installed packages tracked
- **Failed operations**: Any issues encountered
- **Next steps**: Reboot requirements and recommendations

## 🔄 **MicroOS Variants**

The script automatically detects and adapts to:

### **Desktop Variant**
- Uses `pkcon` for package management
- Immediate package installation
- GUI-friendly defaults

### **Server Variant**  
- Uses `transactional-update` for packages
- Requires reboot after updates
- Server-optimized configuration

## 📚 **Additional Resources**

- [openSUSE MicroOS Documentation](https://microos.opensuse.org/)
- [Transactional Updates Guide](https://documentation.suse.com/smart/systems-management/html/Micro-transactional-updates/)
- [MicroOS GitHub](https://github.com/openSUSE/microos-tools)

---

**Generated with Claude Code** 🤖