#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#define BUFSIZE 2048
#define PARAMS "h"
#define USAGE "Usage: %s [-" PARAMS "] [managed if] [monitor if] [ssid]\n"
#define HELP USAGE "\nSimple wifi interface monitoring\n\n" \
"[maclist...] which mac addresses to monitor, empty = all\n" \
"[interface]  which interface to monitor\n" \
"  -h    display this help and exit\n" \
""
#define IEEE80211_FTYPE_MGMT            0x0000
#define IEEE80211_STYPE_PROBE_REQ       0x004
#define IEEE80211_STYPE_PROBE_RESP      0x005

#define CNORMAL  "\033[0m"
#define CRED     "\033[31m"
#define CGREEN   "\033[32m"
#define CYELLOW  "\033[33m"
#define CBLUE    "\033[34m"
#define CMAGENTA "\033[35m"
#define CCYAN    "\033[36m"
#define CWHITE   "\033[37m"

//char * colors[] = {CRED, CGREEN, CYELLOW, CBLUE, CMAGENTA, CCYAN, CWHITE};
typedef int bool;
#define true 1
#define false 0

int sock_man;
int sock_mon;

int maclist_count;
unsigned char * maclist = NULL; //contains mac list

struct wframe
{
	bool nowifi;
	int ts, diffts;
	int type;
	int stype;
	uint16_t nav; //nav in usec
	unsigned char addr1[6];
	unsigned char addr2[6];
	unsigned char addr3[6];
	unsigned char* rxaddr;
	unsigned char* txaddr;

	bool retry;
	bool powermgmt;
};

static bool keepRunning = true;

void intHandler(int dummy) 
{
	if(keepRunning == false)
	{
		exit(0);
	}
    keepRunning = false;
}

struct timespec tsdiff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

int sock_bind(int sock, const char * ifname) { 
    struct sockaddr_ll sll;
    struct ifreq ifr; bzero(&sll , sizeof(sll));
    bzero(&ifr , sizeof(ifr)); 
    strncpy((char *)ifr.ifr_name , ifname, IFNAMSIZ); 
    //copy device name to ifr 
    if((ioctl(sock, SIOCGIFINDEX, &ifr)) == -1)
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
    return sock;
}

int sock_open()
{
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock == -1) {
		if(errno == EPERM)
			printf("You require root priviliges to monitor network data. \n");
		else
			printf("Socket creation failed: %d \n", errno);
		exit(-1);
	}
	return sock;
}

void sock_close()
{
	close(sock_mon);
	close(sock_man);
}

void print_addr(unsigned char* addr)
{
	for(int i = 0; i < 6; i++)
		i == 5 ? printf("%02x", addr[i]) : printf("%02x:", addr[i]);
}

clock_t lastts;
struct wframe * buffertowframe(char * buffer, int size)
{
	//Let's process the packet. 
	//First remove radiotap. 
	struct wframe *frame;
	frame = (struct wframe *) malloc(sizeof(struct wframe));
	memset(frame, 0, sizeof(struct wframe));
	int pos = 0;
	clock_t ts = clock();
	frame->ts = ts;
	frame->diffts = ts - lastts;
	lastts = ts;
	uint8_t radiotap_version = buffer[pos++];
	uint8_t radiotap_pad = buffer[pos++];
	uint16_t radiotap_length = buffer[pos];
	if (radiotap_version != 0 || radiotap_pad != 0 || radiotap_length > 1000) {
		frame->nowifi = true;
		return frame;
	}

	//Skip Radiotap
	pos += radiotap_length - 4 + 2;

	//Decode packet type
	uint16_t fc = buffer[pos]; //frame control info
	pos += 2;
	if((fc & 0x04) != 0) frame->type  += 0x2;
	if((fc & 0x08) != 0) frame->type  += 0x1;
	if((fc & 0x10) != 0) frame->stype += 0x1;
	if((fc & 0x20) != 0) frame->stype += 0x2;
	if((fc & 0x40) != 0) frame->stype += 0x4;
	if((fc & 0x80) != 0) frame->stype += 0x8;
	if(frame->type != IEEE80211_FTYPE_MGMT)
		return NULL;
	if(frame->stype != IEEE80211_STYPE_PROBE_RESP)
		return NULL;
	frame->retry = (fc & 0x400);
	frame->powermgmt = (fc & 0x800);
	frame->nav = buffer[pos];
	pos += 2;
	memcpy(&frame->addr1, buffer+pos, 6); //This address is always there
	pos += 6;
	memcpy(&frame->addr2, buffer+pos, 6);
	pos += 6;
	memcpy(&frame->addr3, buffer+pos, 6);
	pos += 6;

FCS:
	pos += 2; //TODO: Parse sequence number (fcs)
	frame->rxaddr = frame->addr1;
	frame->txaddr = frame->addr2;

	return frame;
}


void analyze(char* buffer, int size)
{
	struct wframe *frame = buffertowframe(buffer, size);
	if(frame == NULL)
		return;
	printf("Probe Reponse\n");
	fflush(stdout);
	free(frame);
}

int probereq(char* ssid, char** req)
{
	//char * req = malloc(BUFSIZE);
	int sz = 4 + 6*3 + 2;
	*req = malloc(BUFSIZE);
	*(req)[0] = 0x40; //Prob Req
	*(req)[1] = 0x0; //Frame control flags
	*(req)[2] = 0x0;
	*(req)[3] = 0x0;
	int p = 4;
	*(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF;
	*(req)[p++] = 0xDE; *(req)[p++] = 0xAD; *(req)[p++] = 0xBE; *(req)[p++] = 0xEF; *(req)[p++] = 0x00; *(req)[p++] = 0x01;
	*(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF; *(req)[p++] = 0xFF;
	*(req)[p++] = 0x40;
	*(req)[p++] = 0x48;
	return sz;
}

int main(int argc, char *argv[])
{
	char buffer[BUFSIZE];
	struct sockaddr saddr_mon;
	struct sockaddr saddr_man;
	int opt;
	struct timespec starttime, endtime;
	clock_gettime(CLOCK_MONOTONIC, &starttime);

	unsigned char bcast[] = "\xFF\xFF\xFF\xFF\xFF\xFF";
	signal(SIGINT, intHandler);

	while ((opt = getopt(argc, argv, PARAMS)) != -1)
	{
		switch (opt)
		{
			case 'h':
				fprintf(stdout, HELP, argv[0]);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, USAGE, argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc - 2)
	{
		fprintf(stderr, USAGE, argv[0]);
		exit(EXIT_FAILURE);
	}

	char * ifaceman = argv[optind];
	char * ifacemon = argv[optind + 1];
	char * ssid = argv[optind + 2];

	sock_man = sock_open();
	sock_mon = sock_open();
	sock_man = sock_bind(sock_man, ifaceman);
	sock_mon = sock_bind(sock_mon, ifacemon);

	char* pkt;
	int sz = probereq(ssid, &pkt);
	printf("pkt: %d\n", pkt[20]);
	socklen_t saddr_size_man = sizeof saddr_man;
	int size = send(sock_man, pkt, sz, 0);
	free(pkt);
	printf("Probe Req. sent (%d), waiting for response...\n", errno);
	fflush(stdout);

	while(keepRunning) {
		socklen_t saddr_size_mon = sizeof saddr_mon;
		int size = recvfrom(sock_mon, buffer, BUFSIZE, 0, &saddr_mon, &saddr_size_mon);
		analyze(buffer, size);
	}
	clock_gettime(CLOCK_MONOTONIC, &endtime);
	printf(CNORMAL);
	sock_close();
	struct timespec ts = tsdiff(starttime, endtime);
	printf("Total Running Time: %ld.%lds\n", ts.tv_sec, ts.tv_nsec / 1000);
	return 0;
}



