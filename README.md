# usock_route
A  kernel module which can route unix domain socket message into localhost port for debugging.

## Why
`unix domain socket` was used as one of important IPC methods in linux, such as _D-BUS_, _systemd_ etc in fundamental services for linux, as well as some user application, *BUT* there is no a good solution for tracing the data on the fly of `unix domain socket`, This link [https://unix.stackexchange.com/questions/219853/how-to-passively-capture-from-unix-domain-sockets-af-unix-socket-monitoring] give some valuable suggetions on this topic. Comparing with caputure data on IP packet using tcpdump(pcap), almost every one of them has some diffculties on their usage. 

## Maybe a better one?
The basic idea is re-route the skb data send/recv by `domain socket` to one free port in one accessable IP address, then the user can use the rich wireshark lua tools to post-process those data further.

## How
Linux provide kprobe for dynamic debugging/tracing the internal of linux. We intercept the unix_dgram_sendmsg/unix_dgram_recvmsg function and copy the user data into a pre-allocated FIFO buffer(size can be assigned by parameter during insmod), at the same time a periodic wake-up daemon process will re-reoute the FIFO data into a unique ADDR:PORT per Process-FD pair which was registered by debugfs interface.

## Usage

### Compiling
1. Make this kernel module in your enviroment (it should not depend on specified kernel version?)
2. insmod usock_route.ko

## Tracing
1. Find the pair of PID:FD which you want to trace, for example: PID : 1, FD : 2
2. Decide which direction you want to trace, S/R (Send or Recv)
3. Use the debugfs add them. f.g ($echo "1 2 S" > /debug/firmware/usock_filter)
4. Check the PORT on previous request. f.g.($cat /debug/firmware/usock_filter)
5. Use tcpdump/wireshark to trace the data.

## Help
Contract me [eshenhu at gmail.com] if you have any suggestion.
