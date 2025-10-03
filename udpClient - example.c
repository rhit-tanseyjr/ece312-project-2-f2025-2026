/************* UDP CLIENT CODE *******************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define SERVER "137.112.38.47"
#define MESSAGE "hi"
#define PORT 2526
#define BUFSIZE 1024

#define VERSION 12
#define DSTPORT 0x1874
#define TYPE 0
#define SRC_PORT 9438


static void put_u8(uint8_t **p, uint8_t v){
    uint8_t* current = *p;
    *current = v;
    current = current+1;
    *p = current;
}

static void put_u16be(uint8_t **p, uint16_t v){
    uint8_t* current = *p;

    *current = (uint8_t)(v>>8);
    current = current + 1;

    *current = (uint8_t)(v & 0xFF);
    current = current + 1;

    *p = current;
}

static uint16_t internet_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint16_t)(((data[0] << 8)) | data[1]);
        data +=2;
        len -=2;
        if (sum & 0x10000) {
            sum = (sum & 0xFFFF) + 1;
        }
        }
        if (len == 1){
            sum += (uint16_t)(data[0] << 8);
        if (sum & 0x10000) {    
            sum = (sum & 0xFFFF) + 1;
        }
    }
    return (uint16_t)~(sum & 0xFFFF);
}

static void byte_to_bits(uint8_t b, char out[9]){
    for (int i =7; i>=0; i--) {
        out[7-i] = (char)('0' + ((b>>i) & 1));
        out[8] = '\0';
    }
}

static void dump_packet(const uint8_t* buf, size_t len) {
    printf("---- Sending packet (%zu bytes) ----\n", len);
    printf(" idx |  bits      | ascii \n");
    printf("--------------------------\n");

    for (size_t i = 0; i < len; i++) {
        char bits[9];
        for (int b = 7; b >= 0; --b)
            bits[7 - b] = ((buf[i] >> b) & 1) ? '1' : '0';
        bits[8] = '\0';

        char c = isprint(buf[i]) ? (char)buf[i] : '.';
        printf("%4zu | %s | %c\n", i, bits, c);
    }
    printf("------------------------------------\n");
}


static void dump_buffer_bits(const uint8_t* buf, size_t len){
    printf(" idx | bits | ascii \n");
    printf("----------------------------------------\n");
    for (size_t i = 0; i < len; ++i) {
        char bits[9]; byte_to_bits(buf[i], bits);
        char ch = isprint(buf[i]) ? (char)buf[i] : '.';
        printf("%4zu | %s | %c\n", i, bits, ch);
    }
    printf("--------------------------------------\n");
}

int main() {
int clientSocket, nBytes;
char buffer[BUFSIZE];
struct sockaddr_in clientAddr, serverAddr;
uint8_t out[BUFSIZE];
uint8_t* w = out;
uint16_t payload_len = (uint16_t)strlen(MESSAGE);

/*Create UDP socket*/
if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("cannot create socket");
    return 0;
}

/* Bind to an arbitrary return address.
* Because this is the client side, we don't care about the address
* since no application will initiate communication here - it will
* just send responses
* INADDR_ANY is the IP address and 0 is the port (allow OS to select port)
* htonl converts a long integer (e.g. address) to a network representation
* htons converts a short integer (e.g. port) to a network representation */
memset((char *) &clientAddr, 0, sizeof (clientAddr));
clientAddr.sin_family = AF_INET;
clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
clientAddr.sin_port = htons(0);

if (bind(clientSocket, (struct sockaddr *) &clientAddr, sizeof (clientAddr)) < 0) {
    perror("bind failed");
    return 0;
}

/* Configure settings in server address struct */
memset((char*) &serverAddr, 0, sizeof (serverAddr));
serverAddr.sin_family = AF_INET;
serverAddr.sin_port = htons(PORT);
serverAddr.sin_addr.s_addr = inet_addr(SERVER);
memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);


put_u8(&w, VERSION);
put_u16be(&w, SRC_PORT);
put_u16be(&w, DSTPORT);

uint16_t len_type = (uint16_t)(((TYPE & 0xF) << 12) | (payload_len & 0x0FFF));
put_u16be(&w, len_type);

size_t bytes_before_checksum = (size_t)(w - out) + payload_len;

bool need_buffer = (bytes_before_checksum % 2) != 0;


memcpy(w, MESSAGE, payload_len);
w += payload_len;
if (need_buffer) {
    put_u8(&w, 0x00);
}
put_u16be(&w, 0x0000);
size_t total_len = (size_t)(w-out);
uint16_t csum = internet_checksum(out, total_len);
out[total_len - 2] = (uint16_t)(csum >> 8);
out[total_len - 1] = (uint8_t)(csum & 0xFF);

printf("Payload length: 0x%04X\n", payload_len);
dump_packet(out, total_len);
printf("Computed checksum: 0x%04X\n", csum);

uint16_t verify = internet_checksum(out, total_len);
printf("Computed checksum: 0x%04X\n", verify);


/* send a message to the server */
if (sendto(clientSocket, out, total_len, 0,
(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
    perror("sendto failed");
    return 0;
}

/* Receive message from server */
nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);

printf("Received from server: %s\n", buffer);
dump_buffer_bits(buffer, (size_t)nBytes);

close(clientSocket);
return 0;
}

