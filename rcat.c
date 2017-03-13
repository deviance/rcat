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

char bcastmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int make_srcaddr(int sockfd, const char *ifname, struct sockaddr_ll *dest_out);
int make_lladdr(const char *mac, struct sockaddr_ll *dest_out);
int Tflag = ETH_P_IP;
void print_addr(struct sockaddr_ll *dest);
void print_addr_str(unsigned char mac[6])
{
	fprintf(stderr, "%2x:%2x:%2x:%2x:%2x:%2x\n", mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5]);
}

struct my_packet {
	struct ether_header hdr;
	unsigned char data[ETHERMTU - sizeof(struct ether_header)];
};

void rwloop(int sockfd, const char *ifname, const char *dest_mac)
{
	char buf[1024];
	int nread_stdin, nread_netfd, nwritten;
	struct sockaddr_ll src;
	struct sockaddr_ll dest;
	struct sockaddr_ll client;
	socklen_t clientsz;
	fd_set master_readfds, readfds, writefds;
	int nready;
	const struct timeval master_timeout = {
		.tv_sec = 60,
		.tv_usec = 0
	};
	struct timeval timeout;

	FD_ZERO(&master_readfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	FD_SET(STDIN_FILENO, &master_readfds);
	FD_SET(sockfd, &master_readfds);

	make_srcaddr(sockfd, ifname, &src);
	make_lladdr(dest_mac, &dest);

	struct my_packet pkt;
	memcpy(&dest, pkt.hdr.ether_dhost, sizeof(pkt.hdr.ether_dhost));
	memcpy(&src,  pkt.hdr.ether_shost, sizeof(pkt.hdr.ether_shost));
	pkt.hdr.ether_type = htons(Tflag);

	fprintf(stderr, "Src: "); print_addr(&src);
	fprintf(stderr, "Dst: "); print_addr(&dest);
	for (;;) {
		readfds = master_readfds;
		timeout = master_timeout;
		nready = select(10, &readfds, &writefds, NULL, &timeout);

		if (nready < 0) {
			perror("select");
			return;
		}

		if (!nready) {
			fprintf(stderr, "Timeout reached.\n");
			return;
		}

		fprintf(stderr, "%d ready\n", nready);
		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			nread_stdin = read(STDIN_FILENO, pkt.data, sizeof(pkt.data));
			if (nread_stdin < 0) {
				perror("read(STDIN_FILENO)");
				break;
			}
			/* STDIN_FILENO gone */
			if (!nread_stdin) {
				fprintf(stderr, "stdin is gone\n");
				FD_CLR(STDIN_FILENO, &master_readfds);
				continue;
			}

			fprintf(stderr, "stdin: %db in\n", nread_stdin);
			FD_SET(sockfd, &writefds);
		}

		if (FD_ISSET(sockfd, &readfds)) {
			nread_netfd = recvfrom(sockfd, buf, sizeof(buf), 0,
				(struct sockaddr *) &client, &clientsz);
			if (nread_netfd < 0) {
				perror("recvfrom(sockfd)");
				break;
			}
			fprintf(stderr, "sockfd: %db in\n", nread_netfd);
			FD_SET(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(STDOUT_FILENO, &writefds)) {
			nwritten = write(STDOUT_FILENO, buf, nread_netfd);
			if (nwritten < 0) {
				perror("write(STDOUT_FILENO)");
				break;
			}
			fprintf(stderr, "stdout: %db out\n", nwritten);
			FD_CLR(STDOUT_FILENO, &writefds);
		}

		if (FD_ISSET(sockfd, &writefds)) {
			nwritten = sendto(sockfd, &pkt, sizeof(pkt.hdr) + nread_stdin, 0,
				(struct sockaddr *) &src, sizeof(src));
			if (nwritten < 0) {
				perror("sendto(sockfd)");
				break;
			}
			fprintf(stderr, "sockfd: %db out\n", nwritten);
			FD_CLR(sockfd, &writefds);
		}
	}
}

void print_addr(struct sockaddr_ll *dest)
{
	fprintf(stderr, "%2x:%2x:%2x:%2x:%2x:%2x\n", dest->sll_addr[0],
		dest->sll_addr[1],
		dest->sll_addr[2],
		dest->sll_addr[3],
		dest->sll_addr[4],
		dest->sll_addr[5]);
}

int make_lladdr(const char *mac, struct sockaddr_ll *dest_out)
{
	struct sockaddr_ll dest;

	if (!mac)
		return -1;

	sscanf(mac, "%2x:%2x:%2x:%2x:%2x:%2x",
		(unsigned int *)&dest.sll_addr[0],
		(unsigned int *)&dest.sll_addr[1],
		(unsigned int *)&dest.sll_addr[2],
		(unsigned int *)&dest.sll_addr[3],
		(unsigned int *)&dest.sll_addr[4],
		(unsigned int *)&dest.sll_addr[5]);

	if (dest_out)
		*dest_out = dest;

	return 0;
}

int make_srcaddr(int sockfd, const char *ifname, struct sockaddr_ll *dest_out)
{
	struct ifreq if_mac, if_idx;
	struct sockaddr_ll dest;

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, strlen(ifname));
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		return -1;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}

	memset(&dest, 0, sizeof(dest));
	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(Tflag);
	/* Index of the network device */
	dest.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	dest.sll_halen = ETH_ALEN;
	/* Destination MAC */
	dest.sll_addr[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	dest.sll_addr[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	dest.sll_addr[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	dest.sll_addr[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	dest.sll_addr[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	dest.sll_addr[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];

	if (dest_out)
		*dest_out = dest;

	return 0;
}

int rawbind(int sockfd, const char *ifname)
{
	struct ifreq if_idx;
	struct sockaddr_ll sockaddr;

	printf("binding to %s\n", ifname);
	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = htons(Tflag);
	/* Index of the network device */
	sockaddr.sll_ifindex = if_idx.ifr_ifindex;

	if (bind(sockfd, (struct sockaddr*) &sockaddr, sizeof(sockaddr))) {
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
	const char *lflag = NULL;
	char src_mac[50], dst_mac[50];
	int tflag = 0;
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
			lflag = optarg;
			break;
		case 'd':
			strcpy(dst_mac, optarg);
			break;
		case 's':
			strcpy(src_mac, optarg);
			break;
		case 't':
			tflag = atoi(optarg);
			Tflag = tflag;
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

	if (lflag) {
		fprintf(stderr, "in listen mode\n");

		rawbind(sockfd, lflag);
		rwloop(sockfd, lflag, NULL);
		return 0;
	}

	if (!strlen(src_mac)) {
		fprintf(stderr, "no source interface specified\n");
		return -1;
	}

	if (!strlen(dst_mac)) {
		fprintf(stderr, "no destination address specified\n");
		return -1;
	}

	fprintf(stderr, "in write mode\n");
	rwloop(sockfd, src_mac, dst_mac);

	return 0;
}
