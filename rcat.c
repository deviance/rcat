/*
 * Copyright (c) 2017 Aleksandr Makarov <aomakarov@outlook.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/select.h>
#include <linux/if_vlan.h>

struct my_packet {
	struct ether_header hdr;
	unsigned char data[ETHERMTU - sizeof(struct ether_header)];
};

int split_hwaddr(const char *macstr, unsigned char hwaddr[6]);
int get_iface_hwaddr(int sockfd, const char *iface, unsigned char hwaddr[6]);
int get_iface_index(int sockfd, const char *iface, int *index);
void print_addr(unsigned char mac[6]);

void rwloop(int sockfd, const char *src, const char *dst, unsigned short proto)
{
	char buf[ETHERMTU];
	int nread_stdin,
	    nread_netfd,
	    nwritten;
	struct sockaddr_ll sll_src;
	struct sockaddr_ll sll_client;
	socklen_t clientsz;
	fd_set master_readfds,
	       readfds,
	       writefds;
	int nready;
	const struct timeval master_timeout = {
		.tv_sec = 60,
		.tv_usec = 0
	};
	struct timeval timeout;
	struct my_packet pkt;

	FD_ZERO(&master_readfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	FD_SET(STDIN_FILENO, &master_readfds);
	FD_SET(sockfd, &master_readfds);

	if (src) {
		/* Setup a source struct sockaddr_ll */
		memset(&sll_src, 0, sizeof(sll_src));
		/* Only interface name must be passed. */
		if (get_iface_hwaddr(sockfd, src, sll_src.sll_addr))
			return;

		fprintf(stderr, "%s hwaddr is ", src); print_addr(sll_src.sll_addr);

		if (get_iface_index(sockfd, src, &sll_src.sll_ifindex))
			return;

		fprintf(stderr, "%s index is %d\n", src, sll_src.sll_ifindex);

		sll_src.sll_family = AF_PACKET;
		sll_src.sll_protocol = htons(proto);
		sll_src.sll_halen = ETH_ALEN;
		memcpy(pkt.hdr.ether_shost, sll_src.sll_addr, sizeof(pkt.hdr.ether_shost));
	}

	if (dst) {
		/* Destination may be either an interface name or a hw address. */
		if (split_hwaddr(dst, pkt.hdr.ether_dhost) &&
		    get_iface_hwaddr(sockfd, dst, pkt.hdr.ether_dhost))
			return;

		fprintf(stderr, "%s hwaddr is ", dst); print_addr(pkt.hdr.ether_dhost);
	}

	if (proto >= 0)
		pkt.hdr.ether_type = htons(proto);

	for (;;) {
		readfds = master_readfds;
		timeout = master_timeout;
		nready = select(10, &readfds, &writefds, NULL, &timeout);

		if (nready < 0) {
			perror("select");
			return;
		}

		if (!nready) {
			fprintf(stderr, "select: timeout reached.\n");
			return;
		}

		fprintf(stderr, "%d ready\n", nready);
		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			nread_stdin = read(STDIN_FILENO, pkt.data, sizeof(pkt.data));
			if (nread_stdin < 0) {
				perror("read: STDIN");
				break;
			}
			/* STDIN_FILENO gone */
			if (!nread_stdin) {
				fprintf(stderr, "stdin is gone\n");
				break;
			}

			fprintf(stderr, "stdin: %db in\n", nread_stdin);
			FD_SET(sockfd, &writefds);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			nread_netfd = recvfrom(sockfd, buf, sizeof(buf), 0,
				(struct sockaddr *) &sll_client, &clientsz);
			if (nread_netfd < 0) {
				perror("recvfrom: sockfd");
				break;
			}
			fprintf(stderr, "sockfd: %db in\n", nread_netfd);
			FD_SET(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(STDOUT_FILENO, &writefds)) {
			nwritten = write(STDOUT_FILENO, buf, nread_netfd);
			if (nwritten < 0) {
				perror("write: STDOUT");
				break;
			}
			fprintf(stderr, "stdout: %db out\n", nwritten);
			FD_CLR(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(sockfd, &writefds)) {
			nwritten = sendto(sockfd, &pkt, sizeof(pkt.hdr) + nread_stdin, 0,
				(struct sockaddr *) &sll_src, sizeof(sll_src));
			if (nwritten < 0) {
				perror("sendto: sockfd");
				break;
			}
			fprintf(stderr, "sockfd: %db out\n", nwritten);
			FD_CLR(sockfd, &writefds);
		}
	}
}

int get_iface_hwaddr(int sockfd, const char *iface, unsigned char hwaddr[6])
{
	struct ifreq if_mac;

	if (!iface)
		return -1;

	memset(&if_mac, 0, sizeof(if_mac));
	strncpy(if_mac.ifr_name, iface, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("ioctl: SIOCGIFHWADDR");
		return -1;
	}

	memcpy(hwaddr, if_mac.ifr_hwaddr.sa_data, 6);

	return 0;
}

void print_addr(unsigned char mac[6])
{
	fprintf(stderr, "%2x:%2x:%2x:%2x:%2x:%2x\n", mac[0], mac[1],
	        mac[2], mac[3], mac[4], mac[5]);
}

int get_iface_index(int sockfd, const char *iface, int *index)
{
	struct ifreq if_idx;

	memset(&if_idx, 0, sizeof(if_idx));
	strncpy(if_idx.ifr_name, iface, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("ioctl: SIOCGIFINDEX");
		return -1;
	}

	*index = if_idx.ifr_ifindex;

	return 0;
}

int split_hwaddr(const char *macstr, unsigned char hwaddr[6])
{
	/* hh for a pointer to a signed char or unsigned char */
	if (sscanf(macstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	    &hwaddr[0], &hwaddr[1], &hwaddr[2], &hwaddr[3],
	    &hwaddr[4], &hwaddr[5]) != 6)
		return -1;

	return 0;
}

int rawbind(int sockfd, const char *ifname, unsigned short protocol)
{
	struct sockaddr_ll sockaddr;

	/* Get the index of the interface to send on */
	if (get_iface_index(sockfd, ifname, &sockaddr.sll_ifindex))
		return -1;

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = htons(protocol);

	if (bind(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr))) {
		perror("bind");
		return -1;
	}

	return 0;
}

void usage() {
	const char usage_str[] = {
		"usage: rcat [--ethertype type] [--source iface] [--destination iface] [--listen iface]"
	};

	printf("%s\n", usage_str);
}

int main(int argc, char *argv[])
{
	int sockfd;
	int c;
	char src_iface[IFNAMSIZ] = {0},
	     dst_addr[IFNAMSIZ] = {0},
	     listen_iface[IFNAMSIZ] = {0};
	int ethertype = 0;
	static struct option long_options[] = {
		{"listen",        required_argument, 0, 'l'},
		{"source",        required_argument, 0, 's'},
		{"destination",   required_argument, 0, 'd'},
		{"ethertype",     required_argument, 0, 't'},
		{"help",          no_argument,       0, 'h'},
		{0,               0,                 0,  0 }
	};

	if (argc < 2) {
		printf("Not enough arguments\n");
		usage();
		return -1;
	}

	for (;;) {
		c = getopt_long(argc, argv, "hs:d:t:l:",
			long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 'l':
			strncpy(listen_iface, optarg, sizeof(listen_iface));
			break;
		case 'd':
			strncpy(dst_addr, optarg, sizeof(dst_addr));
			break;
		case 's':
			strncpy(src_iface, optarg, sizeof(src_iface));
			break;
		case 't':
			ethertype = atoi(optarg);
			break;
		case 'h':
			usage();
			return 0;
		default:
			return -1;
		}
	}

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		return -1;
	}

	if (!ethertype)
		ethertype = ETH_P_IP;

	if (*listen_iface) {
		fprintf(stderr, "listening on %s\n", listen_iface);

		if (rawbind(sockfd, listen_iface, ethertype)) {
			fprintf(stderr, "rawbind: could not bind to %s\n",
			        listen_iface);
		}
		rwloop(sockfd, NULL, NULL, -1);
		return 0;
	}

	if (!*src_iface) {
		fprintf(stderr, "no source interface specified\n");
		return -1;
	}

	if (!*dst_addr) {
		fprintf(stderr, "no destination address specified\n");
		return -1;
	}

	fprintf(stderr, "src: %s, dst: %s\n", &src_iface[0], &dst_addr[0]);
	rwloop(sockfd, &src_iface[0], &dst_addr[0], ethertype);

	return 0;
}
