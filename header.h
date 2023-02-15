#include <string.h>
#include <map>

#define ETHER_ADDR_LEN 6
using namespace std;

struct MAC{
	u_char MAC_a[6];
	bool operator <(const MAC& var) const
	{
		return memcmp(MAC_a,var.MAC_a,sizeof(MAC)) < 0;
	}
};


struct Ether{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct Ip{
	u_int ip_v:4,
	      ip_hl:4;
	u_char ip_tos;
	u_short ip_id;
	u_short ip_off;
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	u_int ip_src;
	u_int ip_dst;
};

struct Packet{
	Ether eth;
	Ip ip;
};

struct Values{
	u_int Tx_packets;
	u_int Tx_bytes;
	u_int Rx_packets;
	u_int Rx_bytes;
	u_int total_packets;
	u_int total_bytes;
};



struct MAC_key{
    u_char src_mac[6];
    u_char dst_mac[6];
    bool operator <(const MAC_key& var) const
    {
        if(memcmp(src_mac, var.src_mac, sizeof(src_mac)) != 0){
            return memcmp(src_mac, var.src_mac, sizeof(src_mac)) < 0;
        }else{
            return memcmp(dst_mac, var.dst_mac, sizeof(dst_mac)) < 0;
        }
    }
};

struct IP_key{
    u_int src_ip;
    u_int dst_ip;
    bool operator <(const IP_key& var) const
    {
        if(src_ip != var.src_ip){
            return src_ip < var.src_ip;
        }else{
            return dst_ip < var.dst_ip;
        }
    }
};

void ip_conversations(map<IP_key, Values>&conv, IP_key key, struct pcap_pkthdr* header){
    map<IP_key, Values>::iterator iter;
    iter = conv.find(key);
    if(iter == conv.end()){

        Values val;
        val.Rx_bytes = 0;
        val.Rx_packets = 0;
        val.total_packets = 1;
        val.total_bytes = header->caplen;
        val.Tx_packets = 1;
        val.Tx_bytes = header->caplen;

        conv.insert(pair<IP_key, Values>(key, val));

    }else{
        iter->second.Tx_packets++;
        iter->second.Tx_bytes += header->caplen;
        iter->second.total_packets++;
        iter->second.total_bytes += header->caplen;
    }
}

void mac_conversations(map<MAC_key, Values>&conv, MAC_key key, struct pcap_pkthdr* header){
    map<MAC_key, Values>::iterator iter;
    iter = conv.find(key);
    if(iter == conv.end()){
        Values var;
        var.Rx_bytes = 0;
        var.Rx_packets = 0;
        var.total_packets = 1;
        var.total_bytes = header->caplen;
        var.Tx_packets = 1;
        var.Tx_bytes = header->caplen;

        conv.insert(pair<MAC_key, Values>(key, var));

    }else{
        iter->second.Tx_packets++;
        iter->second.Tx_bytes += header->caplen;
        iter->second.total_packets++;
        iter->second.total_bytes += header->caplen;
    }
}

void join_mac_conversations(map<MAC_key, Values>&conv){
    map<MAC_key, Values>::iterator iter;

    for(iter = conv.begin(); iter != conv.end(); ++iter){
        MAC_key key;
        memcpy(key.src_mac, iter->first.dst_mac, sizeof(key.src_mac));
        memcpy(key.dst_mac, iter->first.src_mac, sizeof(key.dst_mac));

        map<MAC_key, Values>::iterator inner_iter = conv.find(key);
        if( inner_iter != conv.end()){
            iter->second.Rx_bytes += inner_iter->second.Tx_bytes;
            iter->second.Rx_packets += inner_iter->second.Tx_packets;
            iter->second.total_bytes += inner_iter->second.total_bytes;
            iter->second.total_packets += inner_iter->second.total_packets;
            conv.erase(inner_iter);
        }
    }
}

void join_ip_conversations(map<IP_key, Values>&conv){
    map<IP_key, Values>::iterator iter;

    for(iter = conv.begin(); iter != conv.end(); ++iter){
        IP_key key;
        key.src_ip = iter->first.dst_ip;
        key.dst_ip = iter->first.src_ip;

        map<IP_key, Values>::iterator inner_iter = conv.find(key);
        if( inner_iter != conv.end()){
            iter->second.Rx_bytes += inner_iter->second.Tx_bytes;
            iter->second.Rx_packets += inner_iter->second.Tx_packets;
            iter->second.total_bytes += inner_iter->second.total_bytes;
            iter->second.total_packets += inner_iter->second.total_packets;
            conv.erase(inner_iter);
        }
    }
}

void print_MAC(const uint8_t *addr, char * dst){
    sprintf(dst, "%02X:%02X:%02X:%02X:%02X:%02X",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}

void ntoa(u_int ip, char* dst){
    sprintf(dst, "%d.%d.%d.%d", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}

void print_ip_conversations(map<IP_key, Values>&conv){
    map<IP_key, Values>::iterator iter;
    printf("---------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("|    Address A     |    Address B     |    Packets    |     Bytes     |  Packets A->B |   Bytes A->B  |  Packets B->A |   Bytes B->A  |\n");
    printf("---------------------------------------------------------------------------------------------------------------------------------------\n");
    for(iter = conv.begin(); iter != conv.end(); ++iter){
        char src[18], dst[18];
        ntoa((*iter).first.src_ip, src);
        ntoa((*iter).first.dst_ip, dst);

        printf("|%18s|%18s|%15d|%15d|%15d|%15d|%15d|%15d|\n", src, dst, (*iter).second.total_packets,(*iter).second.total_bytes,
         (*iter).second.Tx_packets, (*iter).second.Tx_bytes, (*iter).second.Rx_packets, (*iter).second.Rx_bytes);
        printf("---------------------------------------------------------------------------------------------------------------------------------------\n");
    }
}


void print_mac_conversations(map<MAC_key, Values>&conv){
    map<MAC_key, Values>::iterator iter;
    char src[40];
    char dst[40];

    printf("-----------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("|     Address A     |     Address B     |    Packets    |     Bytes     |  Packets A->B |   Bytes A->B  |  Packets B->A |   Bytes B->A  |\n");
    printf("-----------------------------------------------------------------------------------------------------------------------------------------\n");

    for(iter = conv.begin(); iter != conv.end(); ++iter){
        print_MAC(iter->first.src_mac, src);
        print_MAC(iter->first.dst_mac, dst);
        printf("|%19s|%19s|%15d|%15d|%15d|%15d|%15d|%15d|\n", src, dst, (*iter).second.total_packets,(*iter).second.total_bytes,
         (*iter).second.Tx_packets, (*iter).second.Tx_bytes, (*iter).second.Rx_packets, (*iter).second.Rx_bytes);
        printf("-----------------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
