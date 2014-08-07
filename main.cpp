#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#define BUFSIZE 2048
#define IEEE80211_FTYPE_MGMT            0x0000
#define IEEE80211_FTYPE_CTL             0x0004
#define IEEE80211_FTYPE_DATA            0x0008

int sock;

struct wframe
{
	bool nowifi;
	int type;
	int stype;
	uint16_t nav; //nav in usec

	bool retry;
	bool powermgmt;
};

int sock_bind() { 
    struct sockaddr_ll sll;
    struct ifreq ifr; bzero(&sll , sizeof(sll));
    bzero(&ifr , sizeof(ifr)); 
    strncpy((char *)ifr.ifr_name ,"hwsim0" , IFNAMSIZ); 
    //copy device name to ifr 
    if((ioctl(sock, SIOCGIFINDEX , &ifr)) == -1)
    { 
        perror("Unable to find interface index");
        exit(-1); 
    }
    sll.sll_family = AF_PACKET; 
    sll.sll_ifindex = ifr.ifr_ifindex; 
    sll.sll_protocol = htons(ETH_P_ALL); 
    if((bind(sock , (struct sockaddr *)&sll , sizeof(sll))) ==-1)
    {
        perror("bind: ");
        exit(-1);
    }
    return 0;
}

int sock_open()
{
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock == -1) {
		if(errno == EPERM)
			printf("You require root priviliges to monitor network data. ");
		else
			printf("Socket creation failed: %d", errno);
		return errno;
	}
	if (sock_bind()) return errno;
	return 0;
}

void sock_close()
{
	close(sock);
}

struct wframe buffertowframe(char * buffer, int size)
{
	//Let's process the packet. 
	//First remove radiotap. 
	struct wframe frame;
	int pos = 0;
	uint8_t radiotap_version = buffer[pos++];
	uint8_t radiotap_pad = buffer[pos++];
	uint16_t radiotap_length = buffer[pos];
	if (radiotap_version != 0 || radiotap_pad != 0 || radiotap_length > 1000) {
		frame.nowifi = true;
		return frame;
	}

	//Skip Radiotap
	pos += radiotap_length - 4 + 2;

	//Decode packet type
	uint16_t fc = buffer[pos]; //frame control info
	pos += 2;
	frame.type = frame.stype = 0;
	if((fc & 0x04) != 0) frame.type  += 0x2;
	if((fc & 0x08) != 0) frame.type  += 0x1;
	if((fc & 0x10) != 0) frame.stype += 0x1;
	if((fc & 0x20) != 0) frame.stype += 0x2;
	if((fc & 0x40) != 0) frame.stype += 0x4;
	if((fc & 0x80) != 0) frame.stype += 0x8;
	frame.retry = (fc & 0x400);
	frame.powermgmt = (fc & 0x800);
	frame.nav = buffer[pos];
	pos += 2;


	fprintf(stderr, "Packet %d: \n", size);
	fprintf(stderr, "Type: %d %d\n", frame.type, frame.stype);
	for(int i = pos; i < size; i++)
		fprintf(stderr, "%x ", buffer[i] & 0xFF);
	fprintf(stderr, "\n");
	return frame;
}

void print_nowifi(char* buffer)
{
	printf("Non-wifi packet\n");
}

void analyze(char* buffer, int size)
{
	wframe frame = buffertowframe(buffer, size);
}

int main()
{
	char buffer[BUFSIZE];
	struct sockaddr saddr;
	if (sock_open()) return 0;

	for(;;) {
		socklen_t saddr_size = sizeof saddr;
		int size = recvfrom(sock, buffer, BUFSIZE, 0, &saddr, &saddr_size);
		analyze(buffer, size);
	}

	sock_close();
	return 0;
}



