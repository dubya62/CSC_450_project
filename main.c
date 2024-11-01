#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define BUF_SIZE 1024

FILE* convert_pcap_to_csv(char* filename, char* outputFilename){
    char buffer[BUF_SIZE];

    snprintf(buffer, BUF_SIZE, "tshark -r %s -T fields -Eseparator=',' -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.len -e tcp.time_delta -e _ws.col.info", filename);

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
    if (**ptr != '"') PANIC("Expected '\"' at start of column, got '%.*s'", 8, *ptr);
    *ptr += 1;

    char *ret = *ptr;

    char skip = 0;
    for (;**ptr && **ptr != '"'; *ptr += 1) {
        if (skip) {
            skip = 0;
            continue;
        }

        if (**ptr == '\\') skip = 1;
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
Row *parse_csv(path)
    const char *path;
{

    Rows rows = { 0 };
    FILE *fp = fopen(path, "r");
    if (!fp) PANIC("Cannot open file for reading '%s': %m", path);

    char buf[BUF_SIZE] = { 0 };
    fgets(buf, BUF_SIZE, fp); // skip first line
    while (fgets(buf, BUF_SIZE, fp)) {
        size_t len = strlen(buf);
        if (buf[len - 1] == '\n') buf[--len] = '\0';
        char *line = strdup(buf);
        Row row = { 0 };
        row.no = atoi(read_column(&line));
        row.time = atof(read_column(&line));
        row.source = strdup(read_column(&line));
        row.destination = strdup(read_column(&line));
        row.protocol = atoi(read_column(&line));
        row.length = atol(read_column(&line));
        row.tcp_segment_len = atoi(read_column(&line));
        row.tcp_delta = atof(read_column(&line));
        row.info = *line ? strdup(read_column(&line)) : NULL;
        da_append(&rows, row);
    }

    for (size_t i = 0; i < rows.count; ++i) {
        printf("info %d = %d\n", i, rows.items[i].no);
    }
    return NULL;
}

int main(void)
{
    parse_csv("output.csv");
    return 0;
}
