#!/bin/bash

# test-vlan-connectivity.sh
# Comprehensive VLAN connectivity testing and validation script
# Tests network connectivity, routing, and security policies between VLANs

set -euo pipefail

# Configuration
BRIDGE_NAME="br0"
TIMEOUT=5

# VLAN test configuration
declare -A VLAN_TESTS=(
    [10]="192.168.10.0/28:Management:192.168.10.1"
    [20]="192.168.20.0/24:LAN:192.168.20.1"
    [30]="192.168.30.0/28:DMZ:192.168.30.1"
    [40]="192.168.40.0/26:Guest:192.168.40.1"
)

# Test targets for connectivity validation
declare -A TEST_TARGETS=(
    ["internet"]="8.8.8.8"
    ["cloudflare"]="1.1.1.1"
    ["google_dns"]="8.8.4.4"
)

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging functions
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED_TESTS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED_TESTS++)); }

# Increment test counter
test_start() {
    ((TOTAL_TESTS++))
}

# Display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Test VLAN connectivity and network configuration

Options:
    --vlan ID           Test specific VLAN only
    --quick             Run quick tests only
    --detailed          Run detailed tests with network analysis
    --security          Test security policies and isolation
    --performance       Run performance tests
    --continuous        Run continuous monitoring
    --report            Generate detailed report
    -h, --help          Show this help message

Examples:
    $0                          # Run all standard tests
    $0 --vlan 10               # Test only VLAN 10
    $0 --detailed --security   # Run detailed tests with security validation
    $0 --continuous            # Monitor network continuously
EOF
}

# Parse arguments
parse_args() {
    TEST_VLAN=""
    QUICK_TEST=false
    DETAILED_TEST=false
    SECURITY_TEST=false
    PERFORMANCE_TEST=false
    CONTINUOUS_TEST=false
    GENERATE_REPORT=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --vlan)
                TEST_VLAN="$2"
                shift 2
                ;;
            --quick)
                QUICK_TEST=true
                shift
                ;;
            --detailed)
                DETAILED_TEST=true
                shift
                ;;
            --security)
                SECURITY_TEST=true
                shift
                ;;
            --performance)
                PERFORMANCE_TEST=true
                shift
                ;;
            --continuous)
                CONTINUOUS_TEST=true
                shift
                ;;
            --report)
                GENERATE_REPORT=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Get VLAN information
get_vlan_info() {
    local vlan_id="$1"
    local config="${VLAN_TESTS[$vlan_id]}"
    
    IFS=':' read -r network description gateway <<< "$config"
    
    echo "network=$network"
    echo "description=$description"
    echo "gateway=$gateway"
}

# Test basic VLAN interface functionality
test_vlan_interface() {
    local vlan_id="$1"
    local vlan_name="${BRIDGE_NAME}.${vlan_id}"
    
    eval "$(get_vlan_info "$vlan_id")"
    
    echo -e "\n${CYAN}=== Testing VLAN $vlan_id Interface ($description) ===${NC}"
    
    # Test 1: Interface exists
    test_start
    if ip link show "$vlan_name" >/dev/null 2>&1; then
        success "Interface $vlan_name exists"
    else
        fail "Interface $vlan_name does not exist"
        return 1
    fi
    
    # Test 2: Interface is UP
    test_start
    local state=$(ip link show "$vlan_name" | grep -o "state [A-Z]*" | awk '{print $2}')
    if [[ "$state" == "UP" ]]; then
        success "Interface $vlan_name is UP"
    else
        fail "Interface $vlan_name is $state"
    fi
    
    # Test 3: VLAN ID configuration
    test_start
    if ip -d link show "$vlan_name" | grep -q "vlan id $vlan_id"; then
        success "VLAN ID $vlan_id correctly configured"
    else
        fail "VLAN ID $vlan_id configuration issue"
    fi
    
    # Test 4: Bridge membership
    test_start
    if bridge link show | grep -q "$vlan_name"; then
        success "Interface $vlan_name is properly bridged"
    else
        warn "Interface $vlan_name bridge membership unclear"
    fi
}

# Test VLAN connectivity
test_vlan_connectivity() {
    local vlan_id="$1"
    local vlan_name="${BRIDGE_NAME}.${vlan_id}"
    
    eval "$(get_vlan_info "$vlan_id")"
    
    echo -e "\n${CYAN}=== Testing VLAN $vlan_id Connectivity ===${NC}"
    
    # Test gateway connectivity
    test_start
    if ping -c 2 -W "$TIMEOUT" -I "$vlan_name" "$gateway" >/dev/null 2>&1; then
        success "Gateway $gateway reachable from VLAN $vlan_id"
    else
        fail "Gateway $gateway unreachable from VLAN $vlan_id"
    fi
    
    # Test internet connectivity
    for target_name in "${!TEST_TARGETS[@]}"; do
        local target_ip="${TEST_TARGETS[$target_name]}"
        test_start
        if ping -c 2 -W "$TIMEOUT" -I "$vlan_name" "$target_ip" >/dev/null 2>&1; then
            success "Internet connectivity to $target_name ($target_ip) from VLAN $vlan_id"
        else
            fail "Internet connectivity to $target_name ($target_ip) failed from VLAN $vlan_id"
        fi
    done
    
    # Test DNS resolution
    test_start
    if nslookup google.com "$gateway" >/dev/null 2>&1; then
        success "DNS resolution working via $gateway"
    else
        fail "DNS resolution failed via $gateway"
    fi
}

# Test VLAN routing
test_vlan_routing() {
    local vlan_id="$1"
    local vlan_name="${BRIDGE_NAME}.${vlan_id}"
    
    eval "$(get_vlan_info "$vlan_id")"
    
    echo -e "\n${CYAN}=== Testing VLAN $vlan_id Routing ===${NC}"
    
    # Test routing table entries
    test_start
    if ip route show dev "$vlan_name" | grep -q "$network"; then
        success "Route for $network exists"
    else
        warn "No specific route for $network found"
    fi
    
    # Test default gateway
    test_start
    if ip route show | grep -q "default.*$gateway"; then
        success "Default gateway route via $gateway exists"
    else
        # Check if there's a default route through this VLAN
        if ip route show dev "$vlan_name" | grep -q "default"; then
            success "Default route exists through VLAN $vlan_id"
        else
            warn "No default route through VLAN $vlan_id"
        fi
    fi
}

# Test inter-VLAN security policies
test_security_policies() {
    echo -e "\n${MAGENTA}=== Testing Security Policies ===${NC}"
    
    # Test 1: Management VLAN isolation
    test_start
    info "Testing management VLAN isolation..."
    
    # Try to access management from other VLANs (should fail)
    for vlan_id in 20 30 40; do
        local vlan_name="${BRIDGE_NAME}.${vlan_id}"
        if ip link show "$vlan_name" >/dev/null 2>&1; then
            if ! ping -c 1 -W 2 -I "$vlan_name" 192.168.10.1 >/dev/null 2>&1; then
                success "VLAN $vlan_id properly isolated from management VLAN"
            else
                fail "VLAN $vlan_id can access management VLAN (security issue)"
            fi
        fi
    done
    
    # Test 2: Guest VLAN isolation  
    test_start
    info "Testing guest VLAN isolation..."
    
    if ip link show "${BRIDGE_NAME}.40" >/dev/null 2>&1; then
        # Guest should not access other internal VLANs
        for target_vlan in 10 20 30; do
            local target_ip="192.168.${target_vlan}.1"
            if ! ping -c 1 -W 2 -I "${BRIDGE_NAME}.40" "$target_ip" >/dev/null 2>&1; then
                success "Guest VLAN isolated from VLAN $target_vlan"
            else
                fail "Guest VLAN can access VLAN $target_vlan (security issue)"
            fi
        done
    fi
    
    # Test 3: DMZ access policies
    test_start
    info "Testing DMZ access policies..."
    
    if ip link show "${BRIDGE_NAME}.30" >/dev/null 2>&1; then
        # DMZ should not access internal LANs
        for target_vlan in 10 20; do
            local target_ip="192.168.${target_vlan}.1"
            if ! ping -c 1 -W 2 -I "${BRIDGE_NAME}.30" "$target_ip" >/dev/null 2>&1; then
                success "DMZ properly isolated from VLAN $target_vlan"
            else
                fail "DMZ can access VLAN $target_vlan (potential security issue)"
            fi
        done
    fi
}

# Performance testing
test_performance() {
    echo -e "\n${MAGENTA}=== Performance Testing ===${NC}"
    
    for vlan_id in "${!VLAN_TESTS[@]}"; do
        local vlan_name="${BRIDGE_NAME}.${vlan_id}"
        eval "$(get_vlan_info "$vlan_id")"
        
        if ip link show "$vlan_name" >/dev/null 2>&1; then
            info "Testing VLAN $vlan_id ($description) performance..."
            
            # Latency test
            test_start
            local latency=$(ping -c 5 -W "$TIMEOUT" -I "$vlan_name" "$gateway" 2>/dev/null | \
                           tail -1 | awk -F'/' '{print $5}' | cut -d'.' -f1)
            
            if [[ -n "$latency" ]] && [[ "$latency" -lt 10 ]]; then
                success "VLAN $vlan_id latency: ${latency}ms (good)"
            elif [[ -n "$latency" ]] && [[ "$latency" -lt 50 ]]; then
                warn "VLAN $vlan_id latency: ${latency}ms (acceptable)"
            else
                fail "VLAN $vlan_id latency: ${latency}ms (high)"
            fi
            
            # Bandwidth test (simplified)
            test_start
            if command -v iperf3 >/dev/null 2>&1; then
                info "iperf3 available - detailed bandwidth testing possible"
                success "Performance testing tools available"
            else
                warn "iperf3 not available - limited performance testing"
            fi
        fi
    done
}

# Detailed network analysis
detailed_analysis() {
    echo -e "\n${BLUE}=== Detailed Network Analysis ===${NC}"
    
    # Bridge analysis
    info "Bridge Configuration:"
    echo "  Bridge: $BRIDGE_NAME"
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        echo "  State: $(ip link show "$BRIDGE_NAME" | grep -o "state [A-Z]*" | awk '{print $2}')"
        echo "  MTU: $(ip link show "$BRIDGE_NAME" | grep -o "mtu [0-9]*" | awk '{print $2}')"
    fi
    
    # VLAN filtering status
    info "VLAN Filtering:"
    if bridge vlan show >/dev/null 2>&1; then
        bridge vlan show | head -10
    else
        warn "Bridge VLAN filtering not available or not configured"
    fi
    
    # Network statistics
    info "Network Statistics:"
    for vlan_id in "${!VLAN_TESTS[@]}"; do
        local vlan_name="${BRIDGE_NAME}.${vlan_id}"
        if ip link show "$vlan_name" >/dev/null 2>&1; then
            local stats=$(ip -s link show "$vlan_name" | grep -A2 "RX:")
            echo "  VLAN $vlan_id statistics:"
            echo "    $stats" | tail -2 | sed 's/^/    /'
        fi
    done
    
    # ARP tables
    info "ARP Tables:"
    ip neigh show | head -10
}

# Generate test report
generate_report() {
    local report_file="/tmp/vlan-test-report-$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "VLAN Connectivity Test Report"
        echo "Generated: $(date)"
        echo "Host: $(hostname)"
        echo "=================================="
        echo
        
        echo "Test Summary:"
        echo "  Total Tests: $TOTAL_TESTS"
        echo "  Passed: $PASSED_TESTS"
        echo "  Failed: $FAILED_TESTS"
        echo "  Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
        echo
        
        echo "VLAN Configuration:"
        for vlan_id in "${!VLAN_TESTS[@]}"; do
            eval "$(get_vlan_info "$vlan_id")"
            echo "  VLAN $vlan_id: $network ($description)"
        done
        echo
        
        echo "Network Interfaces:"
        ip addr show | grep -E "^[0-9]+:|inet " | sed 's/^/  /'
        echo
        
        echo "Routing Table:"
        ip route show | sed 's/^/  /'
        echo
        
        if bridge vlan show >/dev/null 2>&1; then
            echo "VLAN Configuration:"
            bridge vlan show | sed 's/^/  /'
        fi
        
    } > "$report_file"
    
    log "Test report generated: $report_file"
}

# Continuous monitoring
continuous_monitoring() {
    log "Starting continuous VLAN monitoring (Ctrl+C to stop)..."
    
    local iteration=1
    while true; do
        echo -e "\n${BLUE}=== Monitoring Iteration $iteration ($(date)) ===${NC}"
        
        # Quick connectivity test for all VLANs
        for vlan_id in "${!VLAN_TESTS[@]}"; do
            local vlan_name="${BRIDGE_NAME}.${vlan_id}"
            eval "$(get_vlan_info "$vlan_id")"
            
            if ip link show "$vlan_name" >/dev/null 2>&1; then
                if ping -c 1 -W 2 -I "$vlan_name" "$gateway" >/dev/null 2>&1; then
                    echo -e "  ${GREEN}✓${NC} VLAN $vlan_id: OK"
                else
                    echo -e "  ${RED}✗${NC} VLAN $vlan_id: FAILED"
                fi
            else
                echo -e "  ${YELLOW}?${NC} VLAN $vlan_id: INTERFACE DOWN"
            fi
        done
        
        ((iteration++))
        sleep 30
    done
}

# Main test execution
run_tests() {
    local test_vlans=()
    
    if [[ -n "$TEST_VLAN" ]]; then
        if [[ -z "${VLAN_TESTS[$TEST_VLAN]:-}" ]]; then
            error "VLAN $TEST_VLAN not found in configuration"
        fi
        test_vlans=("$TEST_VLAN")
    else
        test_vlans=($(printf '%s\n' "${!VLAN_TESTS[@]}" | sort -n))
    fi
    
    # Header
    echo -e "${BLUE}"
    echo "=============================================="
    echo "     VLAN Connectivity Test Suite"
    echo "=============================================="
    echo -e "${NC}"
    echo "Testing VLANs: ${test_vlans[*]}"
    echo "Test time: $(date)"
    echo
    
    # Run interface tests
    for vlan_id in "${test_vlans[@]}"; do
        test_vlan_interface "$vlan_id"
        
        if [[ "$QUICK_TEST" == false ]]; then
            test_vlan_connectivity "$vlan_id"
            test_vlan_routing "$vlan_id"
        fi
    done
    
    # Additional tests based on options
    if [[ "$SECURITY_TEST" == true ]]; then
        test_security_policies
    fi
    
    if [[ "$PERFORMANCE_TEST" == true ]]; then
        test_performance
    fi
    
    if [[ "$DETAILED_TEST" == true ]]; then
        detailed_analysis
    fi
    
    # Summary
    echo -e "\n${BLUE}=== Test Summary ===${NC}"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}All tests passed! ✓${NC}"
        return 0
    else
        echo -e "${RED}$FAILED_TESTS test(s) failed! ✗${NC}"
        return 1
    fi
}

# Main execution
main() {
    parse_args "$@"
    
    # Check if bridge exists
    if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        error "Bridge $BRIDGE_NAME not found. Run setup-host-networking.sh first."
    fi
    
    # Handle special modes
    if [[ "$CONTINUOUS_TEST" == true ]]; then
        continuous_monitoring
        exit 0
    fi
    
    # Run tests
    if run_tests; then
        local exit_code=0
    else
        local exit_code=1
    fi
    
    # Generate report if requested
    if [[ "$GENERATE_REPORT" == true ]]; then
        generate_report
    fi
    
    exit $exit_code
}

# Execute main function
main "$@"