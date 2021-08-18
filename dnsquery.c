/* DNS query
 *
 * based off of:
 *   - https://datatracker.ietf.org/doc/html/rfc1035
 *   - https://datatracker.ietf.org/doc/html/rfc3596
 *
 * understanding compression required some study of strace(1) output
 * from drill(1) and getent(1)
 *
 * this utility doesn't check for buffer overflows in any capacity,
 * and is therefore extremely vulnerable to any form of malicious input
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define BYTE1(x) (x & 0xff)
#define BYTE2(x) ((x>>8)&0xff)

static void e(const char *str)
{
	fputs(str, stderr);
	fputc('\n', stderr);
	exit(1);
}

static void ep(const char *str, int v)
{
	fprintf(stderr, "%s: %d\n", str, v);
	exit(1);
}

static void iter_name(const uint8_t *buf, size_t buf_len, char *name, size_t *name_pos, size_t *index, int recursion)
{
	if (recursion > 5) {
		e("too much compression recursion!");
	}

	size_t l, ln = *name_pos, i = *index;
	while ((l = buf[i++])) {
		/* compression */
		if (l & 0xc0) {
			uint16_t offset = ((uint16_t)(l & ~0xc0) << 8) | buf[i++];
			size_t j = offset;
			iter_name(buf, buf_len, name, &ln, &j, recursion+1);
			break;
		} else {
			memcpy(name+ln, buf+i, l);
			i+=l;
			ln+=l+1;
			name[ln-1] = '.';
		}
	}
	*name_pos = ln;
	*index = i;
}

#define QTYPE_A 1
#define QTYPE_AAAA 28
#define QCLASS_IN 1
static void add_q(uint8_t *q, size_t *index, const char *qname, uint16_t qtype, uint16_t qclass, uint16_t *qdcount_written)
{
	size_t i = *index;

	for (;;) {
		const char *dot = strchr(qname, '.');

		/* fragment length */
		size_t f = dot ? dot - qname : strlen(qname);
		if (f >= UINT8_MAX) e("bad qname");

		q[i++] = f;
		memcpy(q+i, qname, f);
		i+=f;

		if (dot) qname = dot+1;
		else break;
	}
	/* terminator */
	q[i++] = 0;

	q[i++] = BYTE2(qtype);
	q[i++] = BYTE1(qtype);
	q[i++] = BYTE2(qclass);
	q[i++] = BYTE1(qclass);
	*index = i;

	*qdcount_written += 1;
}

int main(int argc, char **argv)
{
	const char *query = "google.com";
	int c, get_aaaa = 0;
	while ((c = getopt(argc, argv, "46d:")) != -1) {
		if (c == '4') get_aaaa = 0;
		else if (c == '6') get_aaaa = 1;
		else if (c == 'd') query = optarg;
		else e("bad options");
	}

	uint8_t q[256], r[1024];

	/* query id */
	getentropy(q, 2);

	/* QR(1) OPCODE(4) AA(1) TC(1) RD(1)
	 * query | standard query */
	q[2] = (0 << 7) | (0 << 3) | (0 << 2) | (0 << 1) | 1;
	/* RA(1) Z(3) RCODE(4) */
	q[3] = 0;

	uint16_t ancount = 0, nscount = 0, arcount = 0;
	q[6] = BYTE2(ancount);
	q[7] = BYTE1(ancount);
	q[8] = BYTE2(nscount);
	q[9] = BYTE1(nscount);
	q[10] = BYTE2(nscount);
	q[11] = BYTE1(nscount);

	size_t i = 12;

	uint16_t qdcount = 0;
	add_q(q, &i, query, get_aaaa ? QTYPE_AAAA : QTYPE_A, QCLASS_IN, &qdcount);
	q[4] = BYTE2(qdcount);
	q[5] = BYTE1(qdcount);

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(53), .sin_addr=inet_addr("127.0.0.1")};
	void *ap = &addr;
	sendto(s, q, i, 0, ap, sizeof addr);

	ssize_t ret = recv(s, r, sizeof r, 0);
	close(s);
	if (ret < 0) {
		perror("recv");
		return 1;
	}

	if (memcmp(q, r, 2)) {
		e("bad ID");
	}

	uint8_t rcode = r[3] & 0xf;
	if (rcode) {
		ep("bad rcode", rcode);
	}

	qdcount = ((uint16_t)r[4] << 8) | r[5];
	ancount = ((uint16_t)r[6] << 8) | r[7];
	if (ancount == 0) {
		e("no answers");
	}

	/* begin parsing RRs */
	i = 12;

	for (size_t j=0; j < qdcount+ancount; j++) {
		char name[64];
		size_t ln = 0;
		iter_name(r, ret, name, &ln, &i, 0);
		name[ln-1] = '\0';
		puts(name);

		/* don't do anything else with query RRs */
		if (j < qdcount) {
			i+=4;
			continue;
		}

		uint16_t type = ((uint16_t)r[i] << 8) | r[i+1];
		i+=2;
		uint16_t class = ((uint16_t)r[i] << 8) | r[i+1];
		i+=2;
		uint32_t ttl = ((uint32_t)r[i] << 24) | ((uint32_t)r[i+1] << 16) |
			((uint32_t)r[i+2] << 8) | r[i+3];
		i+=4;
		printf("ttl: %u\n", (unsigned)ttl);

		uint16_t rdlength = ((uint16_t)r[i] << 8) | r[i+1];
		i+=2;

		if (class == QCLASS_IN) {
			/* desired length */
			uint16_t len_d;
			/* formatting */
			int af;
			const char *ip_class;
			char ip_s[INET6_ADDRSTRLEN];

			if (type == QTYPE_A) {
				len_d = 4;
				af = AF_INET;
				ip_class = "IPv4";
			} else if (type == QTYPE_AAAA) {
				len_d = 16;
				af = AF_INET6;
				ip_class = "IPv6";
			} else {
				ep("unknown qtype", type);
			}
			if (rdlength != len_d) ep("bad record length", rdlength);

			/* address comes over the wire in network order */
			if (!inet_ntop(af, r+i, ip_s, sizeof ip_s)) e("bad address");
			i+=len_d;

			printf("%s: %s\n", ip_class, ip_s);
			continue;
		}
		e("can't interpret answer");
	}

	return 0;
}
