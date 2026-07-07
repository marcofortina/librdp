#ifndef RDP_PLATFORM_SOCKET_H
#define RDP_PLATFORM_SOCKET_H

int rdp_socket_set_nonblocking(int fd, int enabled);
int rdp_socket_set_nodelay(int fd);
int rdp_socket_close(int fd);

#endif
