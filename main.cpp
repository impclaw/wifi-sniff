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

#define IEEE80211_STYPE_CTL_EXT         0x0060
#define IEEE80211_STYPE_BACK_REQ        0x0080
#define IEEE80211_STYPE_BACK            0x0090
#define IEEE80211_STYPE_PSPOLL          0x00A0
#define IEEE80211_STYPE_RTS             0x00B0
#define IEEE80211_STYPE_CTS             0x00C0
#define IEEE80211_STYPE_ACK             0x00D0
#define IEEE80211_STYPE_CFEND           0x00E0
#define IEEE80211_STYPE_CFENDACK        0x00F0

#define IEEE80211_STYPE_ASSOC_REQ       0x0000
#define IEEE80211_STYPE_ASSOC_RESP      0x0010
#define IEEE80211_STYPE_REASSOC_REQ     0x0020
#define IEEE80211_STYPE_REASSOC_RESP    0x0030
#define IEEE80211_STYPE_PROBE_REQ       0x0040
#define IEEE80211_STYPE_PROBE_RESP      0x0050
#define IEEE80211_STYPE_BEACON          0x0080
#define IEEE80211_STYPE_ATIM            0x0090
#define IEEE80211_STYPE_DISASSOC        0x00A0
#define IEEE80211_STYPE_AUTH            0x00B0
#define IEEE80211_STYPE_DEAUTH          0x00C0
#define IEEE80211_STYPE_ACTION          0x00D0

int sock;

struct wdata
{

};

struct wmgmt_beacon {};
struct wmgmt_auth {};
struct wmgmt_assoc {};

struct wframe
{
	bool nowifi;
	int type;
	int stype;
	uint16_t nav; //nav in usec
	unsigned char addr1[6];
	unsigned char addr2[6];
	unsigned char addr3[6];

	bool retry;
	bool powermgmt;
};

const char * subtype_name(int type, int stype)
{
	if (type == IEEE80211_FTYPE_CTL) {
		if (stype == IEEE80211_STYPE_RTS)
			return "RTS";
		if (stype == IEEE80211_STYPE_CTS)
			return "CTS";
		if (stype == IEEE80211_STYPE_ACK)
			return "ACK";
		else
			return "Unknown Control";
	}
	else if (type == IEEE80211_FTYPE_CTL) {
		if (stype == IEEE80211_STYPE_BEACON)
			return "Beacon";
		else
			return "Unknown Management";
	}
	else
		return "Data";
}

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

void print_addr(unsigned char* addr)
{
	for(int i = 0; i < 6; i++)
		i == 5 ? printf("%x", addr[i]) : printf("%x:", addr[i]);
}

struct wframe buffertowframe(char * buffer, int size)
{
	//Let's process the packet. 
	//First remove radiotap. 
	struct wframe frame;
	memset(&frame, 0, sizeof(wframe));
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
	memcpy(&frame.addr1, buffer+pos, 6);
	pos += 6;
	memcpy(&frame.addr2, buffer+pos, 6);
	pos += 6;
	memcpy(&frame.addr3, buffer+pos, 6);
	pos += 6;

	pos += 2; //TODO: Parse sequence number

	return frame;
}

void print_nowifi()
{
	printf("Non-wifi packet\n");
}

void print_wifi(struct wframe frame)
{

}

void analyze(char* buffer, int size)
{
	wframe frame = buffertowframe(buffer, size);
	if(frame.nowifi)
		print_nowifi();
	else
		print_wifi(frame);
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



