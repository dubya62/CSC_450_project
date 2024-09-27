#!/bin/bash

# No., Time, Delta, Source, Destination, TCP Segment Len, Bytes in flight, Calculated window size, Info

if [[ $# -lt 2 ]]; then
    echo "Usage:"
    echo "./convert_pcap.sh <input_file.pcap> <output_file.csv>"
    exit
fi

# setup the column headers
echo "No.,Time,Source,Destination,Protocol,Length,TCP Segment Len,TCP Delta,Info" > $2

# convert the csv file
tshark -r $1 -T fields -Eseparator=',' -E quote=d -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.len -e tcp.time_delta -e _ws.col.info >> $2
