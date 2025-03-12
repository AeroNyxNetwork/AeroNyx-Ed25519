#!/bin/bash
set -e

# Load the TUN module
if [ ! -c /dev/net/tun ]; then
    echo "TUN/TAP device is not available. Creating it..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# Check if TUN/TAP device is available
if [ ! -c /dev/net/tun ]; then
    echo "ERROR: TUN/TAP device is still not available. Cannot continue."
    exit 1
fi

# Setup IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Setup NAT if the environment variable is set
if [ -n "$ENABLE_NAT" ] && [ "$ENABLE_NAT" = "true" ]; then
    echo "Setting up NAT for subnet..."
    
    # Get the default network interface
    DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}')
    if [ -z "$DEFAULT_IFACE" ]; then
        echo "WARNING: Could not determine default network interface."
    else
        echo "Using interface $DEFAULT_IFACE for NAT"
        iptables -t nat -A POSTROUTING -s "${SUBNET:-10.7.0.0/24}" -o "$DEFAULT_IFACE" -j MASQUERADE
    fi
fi

# Run the actual command
exec "$@"
