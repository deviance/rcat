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
#include <time.h>
#include <sys/time.h>

static int verbose = 1;

struct my_packet {
	struct ether_header hdr;
	unsigned char data[ETHERMTU - sizeof(struct ether_header)];
};

int split_hwaddr(const char *macstr, unsigned char hwaddr[6]);
int get_iface_hwaddr(int sockfd, const char *iface, unsigned char hwaddr[6]);
int get_iface_index(int sockfd, const char *iface, int *index);
int sockaddr_for_iface(int sockfd, const char *iface, unsigned short proto, struct sockaddr_ll *sllout);
int make_ethheader(struct ether_header *hdr, const struct sockaddr_ll *src,
                   const struct sockaddr_ll *dst);
char *prettymac(const unsigned char mac[6], char macout[IFNAMSIZ + 1]);

void rwloop(int sockfd, const struct sockaddr_ll *src, const struct sockaddr_ll *dst)
{
	unsigned char stdinbuf[ETHERMTU], netinbuf[ETHERMTU];
	int nread_stdin,
	    nread_netfd,
	    nsent_stdout,
	    nsent_netfd;
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

	FD_ZERO(&master_readfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	FD_SET(STDIN_FILENO, &master_readfds);
	FD_SET(sockfd, &master_readfds);

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

		/* Stdin is gone */
		if (!FD_ISSET(STDIN_FILENO, &master_readfds)) {
			fprintf(stderr, "stdin is gone\n");
			break;
		}

		/* Try read from stdin */
		if (FD_ISSET(STDIN_FILENO, &readfds)) {

			memset(stdinbuf, 0, sizeof(stdinbuf));
			nread_stdin = read(STDIN_FILENO, stdinbuf, ETHERMTU);
			if (nread_stdin < 0) {
				perror("read: STDIN");
				break;
			}

			if (!nread_stdin) {
				FD_CLR(STDIN_FILENO, &master_readfds);
				continue;
			}

			FD_SET(sockfd, &writefds);
		}

		/* Try read from socket */
		if (FD_ISSET(sockfd, &readfds)) {

			memset(netinbuf, 0, sizeof(netinbuf));
			nread_netfd = recvfrom(sockfd, netinbuf, ETHERMTU, 0,
				(struct sockaddr *) &sll_client, &clientsz);

			if (nread_netfd < 0) {
				perror("recvfrom: sockfd");
				break;
			}

			if (verbose) {
				char mac1[IFNAMSIZ + 1], mac2[IFNAMSIZ + 1];
				struct timeval tv;

				gettimeofday(&tv, NULL);

				fprintf(stderr, "%lu.%06lu %s > %s, ethertype 0x%x, length %i\n",
				        tv.tv_sec, tv.tv_usec,
				        prettymac(sll_client.sll_addr, mac1),
				        prettymac(src->sll_addr, mac2),
				        ntohs(src->sll_protocol),
				        nread_netfd);
			}

			FD_SET(STDOUT_FILENO, &writefds);
		}

		/* Try write to stdout */
		if (FD_ISSET(STDOUT_FILENO, &writefds)) {

			const struct my_packet *p = (const struct my_packet *) netinbuf;

			nsent_stdout = write(STDOUT_FILENO, p->data, nread_netfd -
			                 sizeof(p->hdr));

			if (nsent_stdout < 0) {
				perror("write: STDOUT");
				break;
			}

			FD_CLR(STDOUT_FILENO, &writefds);
		}

		/* Try write to socket */
		if (FD_ISSET(sockfd, &writefds)) {

			struct my_packet p;

			if (make_ethheader(&p.hdr, src, dst) < 0) {
				fprintf(stderr, "make_ethheader: error\n");
				return;
			}

			memcpy(p.data, stdinbuf, nread_stdin);

			nsent_netfd = sendto(sockfd, &p,
					  nread_stdin + sizeof(p.hdr), 0,
					  (struct sockaddr *) src,
					  sizeof(*src));

			if (nsent_netfd < 0) {
				perror("sendto: sockfd");
				break;
			}

			if (verbose) {
				char mac1[IFNAMSIZ + 1], mac2[IFNAMSIZ + 1];
				struct timeval tv;

				gettimeofday(&tv, NULL);

				fprintf(stderr, "%lu.%06lu %s > %s, ethertype 0x%x, length %i\n",
				        tv.tv_sec, tv.tv_usec,
				        prettymac(src->sll_addr, mac1),
				        prettymac(dst->sll_addr, mac2),
				        ntohs(src->sll_protocol),
				        nsent_netfd);
			}

			FD_CLR(sockfd, &writefds);
		}
	}

}

/*
 * The sockaddr_ll structure is a device-independent physical-layer
 * address.
 *
 *     struct sockaddr_ll {
 *         unsigned short sll_family;   // Always AF_PACKET
 *         unsigned short sll_protocol; // Physical-layer protocol
 *         int            sll_ifindex;  // Interface number
 *         unsigned short sll_hatype;   // ARP hardware type
 *         unsigned char  sll_pkttype;  // Packet type
 *         unsigned char  sll_halen;    // Length of address
 *         unsigned char  sll_addr[8];  // Physical-layer address
 *     };
 *
 *     When you send packets, it is enough to specify sll_family, sll_addr,
 *     sll_halen, sll_ifindex, and sll_protocol.  The other fields should be
 *     0.  sll_hatype and sll_pkttype are set on received packets for your
 *     information.
 */

int sockaddr_for_iface(int sockfd, const char *iface, unsigned short proto, struct sockaddr_ll *sllout)
{
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(proto);
	sll.sll_halen = ETH_ALEN;
	sll.sll_ifindex = -1;

	if (!iface)
		goto out;

	/* Something not 'eth0' or 'aa:bb:cc:dd:ee:ff' was passed */
	if ((split_hwaddr(iface, sll.sll_addr) < 0) &&
	    (get_iface_hwaddr(sockfd, iface, sll.sll_addr) < 0))
		return -1;

	/* It was an interface name, but could not get index */
	if ((split_hwaddr(iface, sll.sll_addr) < 0) &&
	    (get_iface_index(sockfd, iface, &sll.sll_ifindex) < 0))
		return -2;

out:
	*sllout = sll;
	return 0;
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

char *prettymac(const unsigned char mac[6], char macout[IFNAMSIZ + 1])
{
	sprintf(macout, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	        mac[0], mac[1],
	        mac[2], mac[3],
	        mac[4], mac[5]);

	return macout;
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

int make_ethheader(struct ether_header *hdr, const struct sockaddr_ll *src,
                   const struct sockaddr_ll *dst)
{
	if (!hdr || !src)
		return -1;

	memset(hdr, 0, sizeof(*hdr));

	hdr->ether_type = src->sll_protocol;
	memcpy(hdr->ether_shost, src->sll_addr, sizeof(hdr->ether_shost));

	if (dst)
		memcpy(hdr->ether_dhost, dst->sll_addr, sizeof(hdr->ether_dhost));

	return 0;
}

void usage() {
	const char usage_str[] = {
		"usage: rcat [--ethertype type] [--source iface]\n"
		"            [--destination iface] [--listen iface] [--help]\n"
		"            [--verbose]"
	};

	printf("%s\n", usage_str);
}

const char warn_root_banner[] = {
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
	"@ RUNNING WITH ROOT PRIVILEGES !!! @\n"
	"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
};

int main(int argc, char *argv[])
{
	int sockfd;
	int c;
	char src_iface[IFNAMSIZ + 1] = {0},
	     dst_addr[IFNAMSIZ + 1] = {0},
	     listen_iface[IFNAMSIZ + 1] = {0};
	int ethertype = 0;
	struct sockaddr_ll sll_src, sll_dst;
	int mconnect;
	static struct option long_options[] = {
		{"listen",        required_argument, 0, 'l'},
		{"source",        required_argument, 0, 's'},
		{"destination",   required_argument, 0, 'd'},
		{"ethertype",     required_argument, 0, 't'},
		{"help",          no_argument,       0, 'h'},
		{"verbose",       no_argument,       0, 'v'},
		{0,               0,                 0,  0 }
	};

	if (argc < 2) {
		printf("Not enough arguments\n");
		usage();
		return -1;
	}

	if (!getuid())
		fprintf(stderr, warn_root_banner);

	for (;;) {
		c = getopt_long(argc, argv, "hvs:d:t:l:",
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
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage();
			return 0;
		default:
			return -1;
		}
	}

	if (!ethertype)
		ethertype = ETH_P_IP;

	mconnect = (*src_iface && *dst_addr);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		return -1;
	}

	if (!mconnect && *listen_iface) {

		if (sockaddr_for_iface(sockfd, listen_iface,
		                       ethertype, &sll_src)) {
			fprintf(stderr, "sockaddr_for_iface: error\n");
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &sll_src, sizeof(sll_src))) {
			perror("bind");
			return -1;
		}

		if (verbose)
			fprintf(stderr, "listening on %s\n", listen_iface);

		rwloop(sockfd, &sll_src, NULL);
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

	if (sockaddr_for_iface(sockfd, src_iface,
			       ethertype, &sll_src)) {
		fprintf(stderr, "sockaddr_for_iface: src: error\n");
		return -1;
	}

	if (sockaddr_for_iface(sockfd, dst_addr,
			       ethertype, &sll_dst)) {
		fprintf(stderr, "sockaddr_for_iface: dst: error\n");
		return -1;
	}

	rwloop(sockfd, &sll_src, &sll_dst);

	return 0;
}
