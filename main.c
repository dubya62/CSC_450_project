#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define BUF_SIZE 1024

FILE* convert_pcap_to_csv(char* filename){
    char buffer[BUF_SIZE];

    snprintf(buffer, BUF_SIZE, "tshark -r %s -T fields -Eseparator=',' -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.len -e tcp.time_delta -e tcp.flags -e _ws.col.info", filename);

    FILE* pipe = popen(buffer, "r");

    return pipe;
}

#define DBG(...) do {                             \
    printf("[DBG] %s:%d ", __FILE__, __LINE__);   \
    printf(__VA_ARGS__);                          \
    printf("\n");                                 \
} while (0);

#define PANIC(...) do {                           \
    printf("[PANIC] %s:%d ", __FILE__, __LINE__); \
    printf(__VA_ARGS__);                          \
    printf("\n");                                 \
    exit(1);                                      \
} while (0);

typedef struct {
    int no;
    double time;
    char *source;
    char *destination;
    int protocol;
    size_t length;
    size_t tcp_segment_len;
    double tcp_delta;
    int tcp_flags;
    char *info;
} Row;

char *read_column(ptr)
    char **ptr;
{
    if (**ptr == ',') {
        char *ret = *ptr;
        **ptr = '\0';
        *ptr += 1;
        return ret;
    }

    char *ret = *ptr;

    char skip = 0;
    for (;**ptr; *ptr += 1) {
        if (skip) {
            skip = 0;
            continue;
        }

        if (**ptr == '\\') skip = 1;
        if (**ptr == ',') break;
    }
    *(*ptr)++ = '\0';
    if (**ptr == ',') *ptr += 1;
    return ret;
}

typedef struct {
    Row *items;
    size_t capacity;
    size_t count;
} Rows;

#define da_append(da, item)                                                              \
    do {                                                                                 \
        if ((da)->count >= (da)->capacity) {                                             \
            (da)->capacity = (da)->capacity == 0 ? BUF_SIZE : (da)->capacity*2;   \
            (da)->items = realloc((da)->items, (da)->capacity*sizeof(*(da)->items)); \
            assert((da)->items != NULL && "Buy more RAM lol");                       \
        }                                                                                \
                                                                                         \
        (da)->items[(da)->count++] = (item);                                             \
    } while (0)

// Every pointer is an allocation, so either free or just agree that memory management is boring.
Rows parse_csv(fp)
    FILE* fp;
{
    Rows rows = { 0 };

    char buf[BUF_SIZE] = { 0 };
    while (fgets(buf, BUF_SIZE, fp)) {
        size_t len = strlen(buf);
        if (buf[len - 1] == '\n') buf[--len] = '\0';
        char *line = buf;
        printf("line = %s\n", line);
        Row row = { 0 };
        row.no = atoi(read_column(&line));
        row.time = atof(read_column(&line));
        row.source = strdup(read_column(&line));
        row.destination = strdup(read_column(&line));
        row.protocol = atoi(read_column(&line));
        row.length = atol(read_column(&line));
        row.tcp_segment_len = atoi(read_column(&line));
        row.tcp_delta = atof(read_column(&line));
        char *flags_col = read_column(&line);
        row.tcp_flags = *flags_col ? strtol(flags_col + 2, NULL, 16) : 0;
        row.info = strdup(line);
        da_append(&rows, row);
    }

    for (size_t i = 0; i < rows.count; ++i) {
        printf("info %d = %d\n", i, rows.items[i].no);
    }
    return rows;
}

void print_rows(rows)
    Rows rows;
{
    for (size_t i = 0; i < rows.count; ++i) {
        printf("Row {\n\
    no = %d,\n\
    time = %lf,\n\
    source = \"%s\",\n\
    destination = \"%s\",\n\
    protocol = %d,\n\
    length = %ld,\n\
    tcp_segment_len = %ld,\n\
    tcp_delta = %lf,\n\
    tcp_flags = 0x%04x,\n\
    info = \"%s\",\n\
}\n",
                rows.items[i].no,
                rows.items[i].time,
                rows.items[i].source,
                rows.items[i].destination,
                rows.items[i].protocol,
                rows.items[i].length,
                rows.items[i].tcp_segment_len,
                rows.items[i].tcp_delta,
                rows.items[i].tcp_flags,
                rows.items[i].info
          );
    }
}

/////////////////////////////
// checking the bits of flags to see if SYN, ACK, or SYNACK (0 if neither
#define ACK 1
#define SYN 2
#define SYNACK 3
#define getTcpType(row) (((row.tcp_flags & 0x10) >> 4) | (row.tcp_flags & 0x2))

/////////////////////////////

int main(int argc, char** argv){
    
    if (argc < 2){
        fprintf(stderr, "Please supply the input file as an arg.\n");
        return 1;
    }

    char* filename = argv[1];

    FILE* csvFile = convert_pcap_to_csv(filename);

    Rows rows = parse_csv(csvFile);
    print_rows(rows);


    return 0;
}
