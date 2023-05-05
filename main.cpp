/*
	original source: https://netfilter.org/projects/libnetfilter_queue/index.html
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <string>
#include <cstring> // memset
#include <fstream> // ifstream

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "libnet.h"

using namespace std;

string filename;

void usage() {
	printf("syntax : 1m-block <site list file>\nsample : 1m-block top-1m.txt");
}

int getidx(char ch) {
	// trie구조를 만들 때 사용
	// domain addr는 .,-,알파벳, 0-9 만 가능
	// Host addr host addr는 case-sensitive 하지 않으므로, 대소문자를 같은 idx로 처리
	// 0~9 : '0' ~ '9'
	// 10 ~ 35 : 'a' ~ 'z'
	// 36 : '.'
	// 37 : '-'
	if ( '0' <= ch && ch <= '9')
		return ch - '0';
	else if ('A' <= ch && ch <= 'Z')
		return ch - 'A';
	else if ('a' <= ch && ch <= 'z')
		return ch - 'a';
	else if (ch == '.')
		return 36;
	else if (ch == '-')
		return 37;
	else  // Unexpected input
		return -1;
}

class TrieNode {
public:
    bool isEnd;
    TrieNode* children[38];

    TrieNode() {
        isEnd = false;
        memset(children, 0, sizeof(children)); 
    }

    ~TrieNode() {
        for (int i = 0; i < 38; i++) {
            delete children[i];
        }
    }
};

class Trie {
public:
    Trie() {
        root = new TrieNode();
    }

    ~Trie() {
        delete root;
    }

    void insert(const string& word) {
        TrieNode* current = root;
        for (char c : word) {
            int idx = getidx(c);
            if (idx == -1) {
                return ;
            }
            
            if (current->children[idx] == 0) {
                current->children[idx] = new TrieNode();
            }
            current = current->children[idx];
        }
        current->isEnd = true;
    }

    bool search(const string& word) {
        TrieNode* current = root;
        for (char c : word) {
            int idx= getidx (c);
            if (idx == -1 ){
                return false;
            }
            if (current->children[idx] == 0) {
                return false;
            }
            current = current->children[idx];
        }
        return current->isEnd;
    }

private:
    TrieNode* root;
};

Trie trie;

/*
void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}
*/

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);

		/*
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
		*/
	}

	/*
	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		
		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		
	}

	
	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		dump(data, ret);
		printf("payload_len=%d ", ret);
	}

	fputc('\n', stdout);
	*/
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);
	//printf("entering callback\n");
	u_char *pkt;

	int len = nfq_get_payload(nfa, &pkt);
	
	struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)pkt;
	int idx =0;
	if(ip_hdr->ip_p == 0x06) { //TCP
		idx += ip_hdr->ip_hl * 4;
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(pkt + idx);
		idx += tcp_hdr->th_off * 4;

		if(ntohs(tcp_hdr->th_sport) == 80 || ntohs(tcp_hdr->th_dport) == 80 ) { //HTTP

			string httpdata = (char*)(pkt + idx);
	
			if(httpdata.find("Host: ") != string::npos) { // finds "Host: "" in httpdata
				int n = httpdata.find("Host: ");
				string host = httpdata.substr(n+6);
				n = host.find("\r\n");
				host = host.substr(0, n); // parse host			

				if(trie.search(host)) {
					printf("Blocked HTTP packet to host : %s\n", host.c_str());
					return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				} 
				else {
					printf("Passed HTTP packet to host : %s\n", host.c_str());
				}
			} 
		} 
	} 

	// implicitly pass all other packets! (To much prints!)
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc !=2) {
		usage();
		return -1;
	}
	

	filename = argv[1];
	ifstream inputFile(filename);
	
	if(inputFile.is_open()) {
		printf("Creating block host list DB (trie) from %s...\n", filename.c_str());
		string line, hostAddr;
		while(getline(inputFile, line)) {
			hostAddr = line.substr(line.find(",") + 1);
			trie.insert(hostAddr);
		}
		printf("Done!\n");
	} else {
		printf("Failed to open %s\n", filename);
		return -1;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
	
}
