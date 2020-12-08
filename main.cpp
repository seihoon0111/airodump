#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include <vector>
#include <string>

using namespace std;
typedef struct ss{
    uint8_t a[6];
}ss;
typedef struct sa{
    char a[100];
}sa;
vector<pair<ss,int>> List;
vector <sa> ess;

void usage() {
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump wlan0\n");
}

pcap_t* handle;

int find(const u_char* packet, unsigned int length){	
    uint8_t* p=(uint8_t*)packet;
    ss bssid;
    int beacon;
    sa essid;
    int radio_len=p[2];
    if(length<40){
        return 0;
    }
    if(p[radio_len]!=0x80){
        return 0;
    }
    memcpy(bssid.a,p+radio_len+16,6);
    beacon=0;
    int check=1;

    for(int i=0;i<List.size();i++){
        if(memcmp(bssid.a,List[i].first.a,6)==0){
            List[i].second++;
            beacon=List[i].second;
            check=0;
            break;
        }
    }     
    memcpy(essid.a,p+radio_len+38,p[radio_len+37]);

    if(check==1){
        pair<ss,int> pair=make_pair(bssid,beacon);
        List.push_back(pair);
        ess.push_back(essid);

    }

    return 0;
}

int printit(){
    for(int j=0;j<List.size();j++){
        for(int i=0;i<6;i++){
            printf("%02x",List[j].first.a[i]);
            if(i!=5){
                printf(":");
            }
        }
        if(List[j].second<10){
            printf("  %d          ",List[j].second);
        }
        else{
            printf("  %d         ",List[j].second);        
        }
        printf("%s",ess[j].a);
        printf("\n");
    }
    return 0;
}

int main(int argc, char*argv[]){
        if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }


    while (true) {

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        find(packet, header->len);
        printf("BSSID              beacons    ESSID\n");
        printit();
        printf("-----------------------------------\n");
    }


    pcap_close(handle);
}