# openSUSE MicroOS Setup Script (Simple & Working)

A simple, reliable post-installation script for openSUSE MicroOS that actually works.

## ✅ **What Works**

- ✅ **Simple user validation** - Only rejects actual root (UID 0)
- ✅ **Clean menu system** - Easy to navigate
- ✅ **Test mode** - Works without sudo for testing
- ✅ **Smart package management** - Detects desktop vs server variants
- ✅ **Error handling** - Continues on failures
- ✅ **Logging** - All actions logged to file

## 🚀 **Usage**

### **Production (on openSUSE MicroOS)**
```bash
# Make executable
chmod +x microos-setup.sh

# Run as regular user
./microos-setup.sh
```

### **Testing (any system)**
```bash
# Complete test mode (no sudo, no OS check)
TEST_MODE=true FORCE_RUN=true ./microos-setup.sh

# Test on non-MicroOS (requires sudo)
FORCE_RUN=true ./microos-setup.sh

# Show help
./microos-setup.sh --help
```

## 📋 **Menu Options**

1. **Update System** - Updates all packages
2. **Install Essential Packages** - curl, wget, git, vim, htop, zip, unzip
3. **Install Development Tools** - docker, python3, nodejs, npm, gcc, make
4. **Setup Firewall** - Configures firewalld with SSH access
5. **Setup SSH** - Enables SSH service and generates keys
6. **Install Everything (Quick Setup)** - Does all of the above
7. **Show Log** - View recent log entries
8. **Exit** - Shows summary and exits

## 🔧 **Key Features**

### **Smart Variant Detection**
- **Desktop**: Uses `pkcon` for immediate package installation
- **Server**: Uses `transactional-update` (requires reboot)

### **Test Mode**
- Simulates all operations without making changes
- Perfect for testing and development
- No sudo required

### **Error Recovery**
- Continues if individual packages fail
- Tracks successful and failed operations
- Shows summary at the end

### **Logging**
- All actions logged to `~/microos-setup.log`
- Color-coded output for easy reading
- View logs from within the script

## 🛡️ **Security**

- **User validation**: Refuses to run as root
- **Minimal privileges**: Only requests sudo when needed
- **Firewall setup**: Enables firewall with SSH access
- **SSH keys**: Generates secure key pairs

## 📊 **What Gets Installed**

### **Essential Packages**
- `curl` - Download tool
- `wget` - Download tool  
- `git` - Version control
- `vim` - Text editor
- `htop` - System monitor
- `zip/unzip` - Archive tools

### **Development Tools**
- `docker` - Container platform
- `python3` - Python programming
- `nodejs/npm` - Node.js runtime
- `gcc/make` - Build tools

### **System Services**
- `firewalld` - Firewall service
- `sshd` - SSH server
- Docker service (enabled and started)

## 🔍 **Troubleshooting**

### **"Don't run this script as root"**
```bash
# Check your user
whoami && id -u

# Should NOT be 0 (root)
# Switch to regular user if needed
su - username
```

### **Testing Without MicroOS**
```bash
# Use test mode
TEST_MODE=true FORCE_RUN=true ./microos-setup.sh
```

### **Sudo Issues**
```bash
# Test sudo access
sudo -v

# For testing without sudo
TEST_MODE=true ./microos-setup.sh
```

## 📈 **Advantages Over Complex Version**

1. **Actually works** - No complex validation that breaks
2. **Simple logic** - Easy to understand and modify  
3. **Reliable** - Fewer failure points
4. **Fast** - No unnecessary complexity
5. **Testable** - Complete test mode available

## 📝 **Log File**

All operations are logged to `~/microos-setup.log`:
- Timestamps for all actions
- Success/failure status
- Error messages for troubleshooting

## 🎯 **Perfect For**

- Fresh openSUSE MicroOS installations
- Development environment setup
- Server post-installation configuration
- Learning shell scripting basics

---

**Simple, reliable, and it just works!** 🎉