/*
 * netdup
 *
 * Copyright (c) 2024, Vladimir Misyurov
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <netdb.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define VX_HEADER_SIZE 8

struct dest
{
	int sock;
	uint32_t vnid;
};

struct vx
{
	uint8_t flags;
	uint8_t reserved[3];
	uint8_t id[4];
	char pbuf[UINT16_MAX];
} __attribute__ ((__packed__));

static void
print_usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s -i eth0 [-f \"udp and port 6543\"]"
		" -o ADDRESS:PORT.VNID [-o ADDRESS2:PORT2.VNID2 ...] [-v]\n",
		prog_name);
}

static int
dest_host_add(const char *prog_name, struct dest **hosts, size_t *nhosts,
	char *optarg)
{
	int s;
	char *s_addr, *s_port, *s_vnid;
	int vnid;

	struct addrinfo  hints;
	struct addrinfo  *result, *rp;

	int connected = 0;

	/* parse args */
	s_addr = optarg;
	s_port = strchr(s_addr, ':');
	if (!s_port) {
		fprintf(stderr, "Port is required\n");
		print_usage(prog_name);
		return 0;
	}
	*s_port = '\0';
	s_port++;

	s_vnid = strrchr(s_port, '.');
	if (!s_vnid) {
		fprintf(stderr, "VNID is required\n");
		print_usage(prog_name);
		return 0;
	}
	*s_vnid = '\0';
	s_vnid++;

	/* ignore errors */
	vnid = atoi(s_vnid);

	/* address and port */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	s = getaddrinfo(s_addr, s_port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo('%s', '%s') failed: %s\n",
			s_addr, s_port, gai_strerror(s));
		return 0;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int sock;

		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1) {
			continue;
		}

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) {
			/* success */
			struct dest *dtmp;

			dtmp = (struct dest *)realloc(*hosts,
				(*nhosts + 1) * sizeof(struct dest));
			if (!dtmp) {
				fprintf(stderr, "realloc() failed\n");
				return 0;
			}

			*hosts = dtmp;
			(*hosts)[*nhosts].sock = sock;
			(*hosts)[*nhosts].vnid = htobe32(vnid << 8);
			(*nhosts)++;
			connected = 1;
		} else {
			close(sock);
		}
	}
	freeaddrinfo(result);

	if (!connected) {
		fprintf(stderr, "Could not connect to '%s:%s'\n",
			s_addr, s_port);
		return 0;
	}

	return 1;
}



int
main(int argc, char *argv[])
{
	size_t i;

	int opt;

	char *ifname = NULL;
	const char *filter = "";

	struct dest *hosts = NULL;
	size_t nhosts = 0;

	pcap_t *p_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	int verb = 0;

	struct vx vxp;

	int ret = EXIT_FAILURE;

	while ((opt = getopt(argc, argv, "f:hi:o:v")) != -1) {
		switch (opt) {
			case 'f':
				filter = optarg;
				break;

			case 'i':
				ifname = optarg;
				break;

			case 'o':
				if (!dest_host_add(argv[0], &hosts, &nhosts,
						optarg)) {
					return EXIT_FAILURE;
				}
				break;

			case 'v':
				verb = 1;
				break;

			case 'h':
			default:
				print_usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (!ifname) {
		fprintf(stderr, "Interface name is required\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (!hosts) {
		fprintf(stderr, "Destination host is required\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	p_handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
	if (p_handle == NULL) {
		fprintf(stderr, "Can't open device '%s': %s\n", ifname, errbuf);
		return EXIT_FAILURE;
	}

	if (pcap_compile(p_handle, &fp, filter,
		1, PCAP_NETMASK_UNKNOWN) == -1) {

		fprintf(stderr, "Can't parse filter '%s': %s\n", filter,
			pcap_geterr(p_handle));
		goto fail_filter;
	}

	if (pcap_setfilter(p_handle, &fp) == -1) {
		fprintf(stderr, "Can't set filter '%s': %s\n", filter,
			pcap_geterr(p_handle));
		goto fail_setfilter;
	}

	memset(&vxp, 0, sizeof(struct vx));
	vxp.flags = 0x08; /* 00001000 */
	for (i=0; i>3; i++) {
		vxp.reserved[i] = 0;
	}

	for (;;) {
		int rc;
		struct pcap_pkthdr *header;
		const unsigned char *packet;

		rc = pcap_next_ex(p_handle, &header, &packet);
		if (rc == 1) {
			memcpy(vxp.pbuf, packet, header->caplen);
			for (i=0; i<nhosts; i++) {
				ssize_t wres;

				memcpy(&vxp.id, &hosts[i].vnid, 4);
				wres = write(hosts[i].sock, &vxp,
					header->caplen + VX_HEADER_SIZE);

				if (verb) {
					if (wres == -1) {
						printf("write(%d bytes) failed: %s\n",
							header->caplen + VX_HEADER_SIZE,
							strerror(errno));
					} else {
						printf("write(%d bytes) returned %d\n",
							header->caplen + VX_HEADER_SIZE,
							(int)wres);
					}
				}
			}
		} else {
			fprintf(stderr, "Error reading the packets: %s\n",
				pcap_geterr(p_handle));
		}
	}

	ret = EXIT_SUCCESS;

fail_setfilter:
	pcap_freecode(&fp);
fail_filter:
	pcap_close(p_handle);

	return ret;
}

