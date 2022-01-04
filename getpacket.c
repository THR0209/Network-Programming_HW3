#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

struct p {
    int num;
    char ip[256];
};

struct p count[1000];
int cnt = 0;

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int *id = (int *)arg;
    char tmp[256];

    printf("Packet ID: %d\n", ++(*id));

    /* Time stamp */
    printf("Receive time: %s", ctime(&pkthdr->ts.tv_sec));

    /* Source of MAC Address */
    printf("MAC Address from: ");
    for(int i=0; i<6; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");

    /* Destination of MAC Address */
    printf("MAC Address to: ");
    for(int i=6; i<12; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");

    if(packet[12] == 8 && packet[13] == 0) { // Type IPv4  = 0x0800
        printf("Type: IP\n");

        /* Src IP Address */
        printf("Src IP Address: ");
        for(int i=26; i<29; i++) {
            printf("%d.", packet[i]);
        }
        printf("%d\n", packet[29]);

        /* Dst IP Address */
        printf("Dst IP Address: ");
        for(int i=30; i<33; i++) {
            printf("%d.", packet[i]);
        }
        printf("%d\n", packet[33]);

        /* Protocol */
        printf("Protocol: ");
        if(packet[23] == 6)     printf("TCP\n");
        else if(packet[23] == 17)    printf("UDP\n");
        else    printf("else\n");

        /* Port */
        if(packet[23] == 6 || packet[23] == 17) {  // if the packet is TCP or UDP packet
            printf("Src Port: %d\n", packet[34]*256 + packet[35]);
            printf("Dst Port: %d\n", packet[36]*256 + packet[37]);
        }

        /* Counting the times of transfering */
        sprintf(tmp,"[%d.%d.%d.%d] to [%d.%d.%d.%d]\0", packet[26], packet[27], packet[28], packet[29], packet[30], packet[31], packet[32], packet[33]);
        int flag = 0;
        for(int i=0; i<cnt; i++) {
            if(strcmp(count[i].ip, tmp)==0) {
                flag = 1;
                count[i].num++;
                break;
            }
        }
        if(flag == 0) {
            count[cnt].num=1;
            strcpy(count[cnt].ip, tmp);
            cnt++;
        }
    }

    printf("\n");
}


int main(int argc, char **argv)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE], filename[1024];
    int n=0;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL) {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        return 2;
    }
    printf("device: %s\n", dev);

    pcap_t *device = pcap_open_live(dev, 65535, 1, 0, errbuf);
    if(argc == 3) {
        if(strcmp(argv[1], "-r") == 0) {
            strcpy(filename, argv[2]);
	    printf("%s\n",filename);
            device = pcap_open_offline(filename, errbuf);
            if(device == NULL) {
                fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
                return 2;
            }
            printf("filename: %s\n", filename);
        }
        else if(strcmp(argv[1], "-n") == 0) {
            n = atoi(argv[2]);
        }
        else {
            printf("Usage: \nsudo ./getpacket -r packet_file\nsudo ./getpacket -n packet_num\n");
	    return 0;
        }
    }

    int id = 0;
    pcap_loop(device, n, getPacket, (u_char *)&id);
    printf("--------------------------------------\n\n");
    printf("[Statistics]\n");
    for(int i=0; i<cnt; i++) {
        printf("%s\t%d\n", count[i].ip, count[i].num);
    };
    pcap_close(device);
    return 0;
}
