#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <map>
#include <netinet/ip.h>
#include "header.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* file_;
} Param;

Param param = {
	.file_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->file_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(param.file_,errbuf);

	if(handle == NULL){
		fprintf(stderr,"pcap_open_offline(%s) return null - %s\n",param.file_,errbuf);
	}
	
	struct pcap_pkthdr* header;
	const u_char* data;

	map<u_int,Values> ip_;
	map<MAC,Values> mac_;

	map<IP_key,Values> ip_conv;
	map<MAC_key,Values> mac_conv;

	while(handle != NULL){
		int res = pcap_next_ex(handle,&header,&data);
		
		if(res == 0) continue;
		if(res == -2) break;

		struct Ether* mac_key = (struct Ether*) data;
		struct Ip* ip_key = (struct Ip*)(data+14);
		
		IP_key ipKey;
		MAC_key macKey;
		struct Packet* packet = (struct Packet *) data;

		if(ntohs(mac_key->ether_type)==0x0800){	
			ipKey.src_ip = packet->ip.ip_src;
			ipKey.dst_ip = packet->ip.ip_dst;
			ip_conversations(ip_conv,ipKey,header);
				
			//endpoint
			if(ip_.find(ip_key->ip_dst) == ip_.end()){
				Values val;

				val.Tx_bytes=0;
				val.Rx_bytes=header->len;
				val.Tx_packets=0;
				val.Rx_packets=1;

				ip_.insert(pair<u_int,Values>((ip_key->ip_dst),val));
			}
			else{
				ip_[ip_key->ip_dst].Rx_packets += 1;
				ip_[ip_key->ip_dst].Rx_bytes += header->len;
			}
		
			if(ip_.find(ip_key->ip_src)==ip_.end()){
				Values val;

				val.Tx_bytes=header->len;
				val.Rx_bytes=0;
				val.Tx_packets=1;
				val.Rx_packets=0;

				ip_.insert(pair<u_int,Values>((ip_key->ip_src),val));
			}
			else{
				ip_[ip_key->ip_src].Tx_packets += 1;
				ip_[ip_key->ip_src].Tx_bytes += header->len;
			}
		}
		//conversation
		memcpy(macKey.src_mac,packet->eth.ether_shost,sizeof(macKey.src_mac));
		memcpy(macKey.dst_mac,packet->eth.ether_dhost,sizeof(macKey.dst_mac));

		mac_conversations(mac_conv,macKey,header);
		

		//endpoint
		MAC mac_a_r,mac_a_t;

		memcpy(mac_a_r.MAC_a,mac_key->ether_dhost,sizeof(mac_a_r));
		memcpy(mac_a_t.MAC_a,mac_key->ether_shost,sizeof(mac_a_t));

		if (mac_.find(mac_a_r) == mac_.end()){
			Values val;

		 	val.Tx_bytes=0;
			val.Rx_bytes=header->len;
			val.Tx_packets=0;
			val.Rx_packets=1;

			mac_.insert(pair<MAC,Values>((mac_a_r),val));

		}
		else{
			mac_[mac_a_r].Rx_packets  += 1;
			mac_[mac_a_r].Rx_bytes += header->len;
		}
		if (mac_.find(mac_a_t) == mac_.end()){
			Values val;
	
			val.Tx_bytes=header->len;
			val.Rx_bytes=0;
			val.Tx_packets=1;
			val.Rx_packets=0;
	
			mac_.insert(pair<MAC,Values>((mac_a_t),val));

		}
		else{
			mac_[mac_a_t].Tx_packets  += 1;
			mac_[mac_a_t].Tx_bytes += header->len;
		}
		
	}

	pcap_close(handle);
	join_ip_conversations(ip_conv);
    	join_mac_conversations(mac_conv);
	//print ip endpoint
	printf("<IPv4 Endpoints>\n");
    	printf("------------------------------------------------------------------------------------\n");
    	printf("|     Address      |   Tx Packets  |    Tx Bytes   |   Rx Packets  |    Rx Bytes   |\n");
    	printf("------------------------------------------------------------------------------------\n");
    	map<uint32_t, Values>::iterator iter1;
    	for(iter1 = ip_.begin(); iter1 != ip_.end(); ++iter1){
        	char addr[18];
        	ntoa(iter1->first, addr);

       	 	printf("|%18s|%15d|%15d|%15d|%15d|\n", addr,
         iter1->second.Tx_packets,iter1->second.Tx_bytes, iter1->second.Rx_packets, iter1->second.Rx_bytes);
        	printf("------------------------------------------------------------------------------------\n");
    	}
	//print Ethernet endpoint
	printf("<Ethernet Endpoints>\n");
	printf("------------------------------------------------------------------------------------\n");
	printf("|     Address      |   Tx Packets  |    Tx Bytes   |   Rx Packets  |    Rx Bytes   |\n");
	printf("------------------------------------------------------------------------------------\n");
	map<MAC, Values>::iterator iter_;
	for(iter_ = mac_.begin(); iter_ != mac_.end(); ++iter_){
		printf("|%02X:%02X:%02X:%02X:%02X:%02X |%15d|%15d|%15d|%15d|\n",iter_->first.MAC_a[0],iter_->first.MAC_a[1],iter_->first.MAC_a[2],iter_->first.MAC_a[3],iter_->first.MAC_a[4],iter_->first.MAC_a[5],iter_->second.Tx_packets,iter_->second.Tx_bytes, iter_->second.Rx_packets, iter_->second.Rx_bytes);
        	printf("------------------------------------------------------------------------------------\n");
    	}

	print_ip_conversations(ip_conv);
	print_mac_conversations(mac_conv);


}
