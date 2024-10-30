#include <iostream>
#include <string.h>
#include <pcap.h>
#include <array>
#include <sstream>

typedef struct {
    uint8_t value[6];
} mac_t;


struct __attribute__((aligned(1))) eth_h {
    mac_t dmac;
    mac_t smac;
    uint16_t type;
};

void print_mac(mac_t mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac.value[0], mac.value[1], mac.value[2], mac.value[3], mac.value[4], mac.value[5]);
}

int main(int argc, const char* argv[]) {
    auto prog = basename(argv[0]);

    if(argc != 2) {
        std::cerr << "Usage: " << prog << " <device>" << std::endl;
        return 1;
    }

    char errbuf[BUFSIZ];
    auto* pcap = pcap_open_live(argv[1], 262144, 0, 0, errbuf);
    if(!pcap) {
        std::cerr << errbuf << std::endl;
        return 2;
    }

    while (true)
    {
        struct pcap_pkthdr* hdr;
        const u_char* packet;

        auto res = pcap_next_ex(pcap, &hdr, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            std::cerr << "pcap_next_ex failed : " << pcap_geterr(pcap) << std::endl;
            break;
        }

        auto* eth = (eth_h*)packet;


        auto proc = (uint8_t*)(packet + 9);
        //if(proc == 6)

        packet += sizeof(eth_h);

        auto src_port = ntohs(*(uint16_t*)packet+20);
        auto dst_port = ntohs(*(uint16_t*)packet+22);

        std::cout << "DMAC : ";
        print_mac(eth->dmac);

        std::cout << std::endl << "SMAC : ";
        print_mac(eth->smac);
        std::cout << std::endl;

        std::cout << "SRC IP : ";
        auto src_ip = (std::array<unsigned char, 4>*)(packet+12);
        for(auto i = 0; i < 4; i++) {
            if(i != 0)
                std::cout << ".";
            std::cout << (int)(*src_ip)[i];
        }
        std::cout << ":" << src_port << std::endl;

        std::cout << "DST IP : ";
        auto dst_ip = (std::array<unsigned char, 4>*)(packet+16);
        for(auto i = 0; i < 4; i++) {
            if(i != 0)
                std::cout << ".";
            std::cout << (int)(*dst_ip)[i];
        }
        std::cout << ":" << dst_port << std::endl;



        std::cout << "=============================" << std::endl;

    }

    pcap_close(pcap);

    return 0;

}