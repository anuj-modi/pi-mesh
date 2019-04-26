#!/bin/bash
# kill the WPA supplicant to free the wlan0 interface
sudo pkill wpa_supplicant

#bring down wlan0
sudo ip link set wlan0 down

# set up wlan0 in ad-hoc mode
sudo ifconfig wlan0 mtu 1500
sudo iwconfig wlan0 mode ad-hoc essid rpi-mesh-network
sudo iwconfig wlan0 channel 8

sudo ip link set wlan0 up
