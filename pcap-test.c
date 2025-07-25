#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/if_ether.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1]; //eth0 or wlan
	return true;
}

struct eth_header{
	uint8_t source_mac[ETHER_ADDR_LEN];
	uint8_t dst_mac[ETHER_ADDR_LEN];
};

struct ip_header{
	uint8_t *ip_src; 
	uint8_t *ip_dst;

};

struct tcp_header{
	uint8_t *source_port;
	uint8_t *dst_port;
};

void eth_parser(struct eth_header eth, const u_char* packet){
	//소스맥, 데스맥 저장
		for(int i=0; i<6; i++){
			eth.source_mac[i] = packet[i];
			eth.dst_mac[i] = packet[i+6];
		}

		//소스맥 출력
		printf("source mac address : ");
		for(int i=0; i<6; i++){
			printf("%02x:",eth.source_mac[i]);
		}

		printf("\t");

		//데스맥 출력
		printf("destination mac address : ");
		for(int i=0; i<6; i++){
			printf("%02x:",eth.dst_mac[i]);
		}
		printf("\n");
}

void ip_parser(struct ip_header *ip, const u_char* packet){
	ip->ip_src = (uint8_t *)(packet + 14 + 12);
	ip->ip_dst = (uint8_t *)(packet + 14 + 16);

	printf("source ip address : %d.%d.%d.%d\n", ip->ip_src[0],ip->ip_src[1],ip->ip_src[2],ip->ip_src[3]);
	printf("destination ip address : %d.%d.%d.%d\n", ip->ip_dst[0],ip->ip_dst[1],ip->ip_dst[2],ip->ip_dst[3]);
}

void tcp_parser(struct tcp_header tcp, const u_char* packet){
	tcp.source_port = (uint8_t *)(packet + 34);
	tcp.dst_port = (uint8_t *)(packet + 34 + 2);

	printf("source port : %d\n", ntohs(*(uint16_t *)tcp.source_port));
	printf("destination port : %d\n", ntohs(*(uint16_t*)tcp.dst_port));

	for(int i=0; i<20; i++){
		printf("%02x ", *(packet + 54 + i));
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	struct eth_header eth;
	struct ip_header ip;
	struct tcp_header tcp;
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); //packet open
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet); //packet receive
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		fflush(stdout);
		
		eth_parser(eth, packet);
		ip_parser(&ip, packet);
		tcp_parser(tcp, packet);

		// 질문 : ip는 변경 안해도 되는데 tcp는 왜 변환해야 하나요?
		/*
		//소스맥, 데스맥 저장
		for(int i=0; i<6; i++){
			eth.source_mac[i] = packet[i];
			eth.dst_mac[i] = packet[i+6];
		}

		//소스맥 출력
		for(int i=0; i<6; i++){
			printf("%02x:",eth.source_mac[i]);
		}

		printf("\t");

		//데스맥 출력
		for(int i=0; i<6; i++){
			printf("%02x:",eth.dst_mac[i]);
		}
		printf("\n");
		

		ip.ip_src = (uint8_t *)(packet + 14 + 12);
		ip.ip_dst = (uint8_t *)(packet + 14 + 16);

		printf("%d.%d.%d.%d\n", ip.ip_src[0],ip.ip_src[1],ip.ip_src[2],ip.ip_src[3]);
		printf("%d.%d.%d.%d\n", ip.ip_dst[0],ip.ip_dst[1],ip.ip_dst[2],ip.ip_dst[3]); 

		tcp.source_port = (uint8_t *)(packet + 34);
		tcp.dst_port = (uint8_t *)(packet + 34 + 2);

		printf("%d\n", ntohs(*(uint16_t *)tcp.source_port));
		printf("%d\n", ntohs(*(uint16_t*)tcp.dst_port));
		*/
	}

	pcap_close(pcap);
}
