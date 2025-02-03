# DRONESNIFF-WIFI

- This software is designed to be used on OLIMEX ESP32-EVB-EA-IND, used to detect devices/drones sending WIFI.
- The software is programmed in C++ and developed via PlatformIO.
- The board IP is 192.168.1.10/24
- Detects WIFI UAV DRONE devices.
- "Plug and play", no confgiuration available.

### Set-up function

The module is initialised with Serial communication at 115200 bauds. 

### WiFi Sniffer functions

- *wifi\_sniffer\_init*: Function where are initialised the wifi sniffer, the ring buffer for accumulate all the packets.
- *wifi\_sniffer\_channel\_loop*: Task pinned to core 1. As the configuration is always set for scan\_rid, this function only delays 500 ms for channel looping.
- *wifi\_sniffer\_parse\_task*: Task pinned to core 1. This creates a infinite loop to receive packets from the ring buffer and decode each packet. Also removes the packet from the ring buffer.
- *wifi\_sniffer\_set\_channel*: Function that sets the channel selected to the ESP-32.
- *wifi\_sniffer\_packet\_handler* : Function in charge of receiving all the packets. Depending on the RID protocol, gets the content of the packet and appends it to the ring buffer. It covers ASD-STAN and ASTM. 
