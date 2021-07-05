#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include "packet.hpp"
// #include "basic_utils.hpp"

using namespace std;

#define PACKET_LEN 4096
#define ATTACKER_PORT 4000
#define SERVER_PORT 1024

#define URG_PACKET 0
#define ACK_PACKET 1
#define PSH_PACKET 2
#define RST_PACKET 3
#define SYN_PACKET 4
#define FIN_PACKET 5

int receive_packet(int sockfd, char *buf, size_t len, struct sockaddr_in *dst)
{
    unsigned short dst_port;
    int recvlen;

    /* Clear the memory used to store the datagram */
    memset(buf, 0, len);
    int itr = 0;

    do
    {
        recvlen = recvfrom(sockfd, buf, len, 0, NULL, NULL);
        if (recvlen <= 0)
        {
            break;
        }
        memcpy(&dst_port, buf + 22, sizeof(dst_port));
        cout << dst_port << endl;
    } while (dst_port != dst->sin_port);

    /* Return the amount of recieved bytes */
    return recvlen;
}

int main()
{

    int sockfd,
        sent,
        one = 1;
    short sendPacket = 0;

    struct sockaddr_in src, dest;

    char *packetBuffer = NULL;
    int pBufferLen;

    char *dataBuffer = NULL;
    int sBufferLen;

    uint32_t seqnum;
    uint32_t acknum;

    char *payload = NULL;
    int pLen;

    struct iphdr ip_hdr;
    struct tcphdr tcp_hdr;

    if (!(packetBuffer = (char *)calloc(PACKET_LEN, sizeof(char))))
    {
        cerr << "Could not allocate memory for packet buffer" << endl;
        free(packetBuffer);
    }

    if (!(dataBuffer = (char *)malloc(520)))
    {
        cerr << "Could not allocate memory for data buffer" << endl;
        free(dataBuffer);
    }

    if (!(payload = (char *)malloc(512)))
    {
        cerr << "Could not allocate memory for payload" << endl;
        free(payload);
    }

    strcpy(payload, "Data send.");
    pLen = (strlen(payload) / sizeof(char));

    cout << "Setting up....." << endl;

    cout << "Creating raw socket...." << endl;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (sockfd < 0)
    {
        cerr << "Error creating socket" << endl;
        free(packetBuffer);
        free(dataBuffer);
        free(payload);
    }

    cout << "Configuring server ip...." << endl;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, "127.0.1.1", &dest.sin_addr) != 1)
    {
        cout << "Failed" << endl;
        cerr << "Server ip invalid" << endl;
    }
    cout << "Done configuring server ip" << endl;

    cout << "Configuring attacker ip...." << endl;
    src.sin_family = AF_INET;
    srand(time(NULL));
    int attacker = 1024 + rand() * (65535 - 1024 + 1);
    src.sin_port = htons(attacker);
    if (inet_pton(AF_INET, "127.0.1.1", &src.sin_addr) != 1)
    {
        cout << "Failed" << endl;
        cerr << "Source ip invalid" << endl;
    }
    cout << "Done configuring source ip" << endl;

    cout << "Configuring socket" << endl;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        cout << "Failed" << endl;
        cerr << "Error in configuring socket" << endl;
    }
    cout << "Done configuring socket" << endl;

    memset(packetBuffer, 0, PACKET_LEN);
    create_raw_datagram(packetBuffer, &pBufferLen, SYN_PACKET, &src, &dest, NULL, 0);
    // dump_packet(packetBuffer, pBufferLen);
    if ((sent = sendto(sockfd, packetBuffer, pBufferLen, 0, (struct sockaddr *)&dest,
                       sizeof(struct sockaddr))) < 0)
    {
        cout << "Failed" << endl;
        cerr << "Error in SYN" << endl;
    }

     pBufferLen = receive_packet(sockfd, packetBuffer, DATAGRAM_LEN, &src);
//    pBufferLen = recvfrom(sockfd, packetBuffer, pBufferLen, 0, (struct sockaddr *)&dest, (socklen_t *)sizeof(struct sockaddr));
//    // dump_packet(pckbuf, pckbuflen);
    if (pBufferLen <= 0)
    {
        cout << "Failed" << endl;
        cerr << "Error in SYN + ACK" << endl;
    }

    update_seq_and_ack(packetBuffer, &seqnum, &acknum);

	/* Step 3: Send the ACK-packet, with updated numbers */
	memset(packetBuffer, 0, DATAGRAM_LEN);
	gather_packet_data(dataBuffer, &sBufferLen, seqnum, acknum, NULL, 0);
	create_raw_datagram(packetBuffer, &pBufferLen, ACK_PACKET, &src, &dest, dataBuffer, sBufferLen);
	// dump_packet(pckbuf, pckbuflen);
	if ((sent = sendto(sockfd, packetBuffer, pBufferLen, 0, (struct sockaddr*)&dest, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
		perror("ERROR:");
		
	}
	free(dataBuffer);

    return 0;
}