#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 1024

/////////////////////////////////////////////
// Converting pcap file to csv file
FILE* convert_pcap_to_csv(char* filename, char* outputFilename){
    char buffer[BUF_SIZE];

    snprintf(buffer, BUF_SIZE, "tshark -r %s -T fields -Eseparator=',' -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.len -e tcp.time_delta -e _ws.col.info", filename);

    FILE* pipe = popen(buffer, "r");

    return pipe;
}

/////////////////////////////////////////////
// initializing function





/////////////////////////////////////////////
// initializing function
int main(int argc, char** argv){
    printf("Hello, world!");

    return 0;
}
