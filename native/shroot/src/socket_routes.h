#ifndef MD_SOCKET_ROUTES_H
#define MD_SOCKET_ROUTES_H
#include <sys/un.h>
#define MD_SOCKET_ROUTES_MAX 8
struct md_socket_route { char source[108], destination[108]; int abstract, resources; };
struct md_socket_routes { unsigned count; struct md_socket_route entries[MD_SOCKET_ROUTES_MAX]; };
int md_socket_route_add(struct md_socket_routes *, const char *option, const char *source, const char *destination);
int md_socket_route_apply(const struct md_socket_routes *, struct sockaddr_un *, unsigned *length);
int md_socket_route_option_valid(const char *);
const char *md_socket_route_option(const struct md_socket_route *);
#endif
