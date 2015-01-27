## fixutils
A few utilities that are useful when dealing with the FIX protcol.
#### BinaryToFIX
This command line application can read FIX messages from log files or packet captures (.pcap) and writes CSV containing a row per message with just the fields you want in each row. If the message does not have that field in then a blank is written.

```
usage: org.messageforge.fixutil.bin2fix.BinaryToFIX
-appDict <arg>       Application dictionary
-appOnly             Filter session messages
-compIDs <arg>       Filter Sender/TargetCompIDs (comma separated)
-dir <arg>           Directory (all files will be parsed
-fields <arg>        Fields (comma separated). Use "Bytes" to display the
                      raw message
-filter <arg>        Packet filter
-in <arg>            Input file
-millis              Convert latency to milliseconds
-msgTypes <arg>      Filter message types (comma separated)
-out <arg>           Output file
-pcap                Indicates this is a pcap file and needs reassembly
-sessionDict <arg>   Session dictionary (or both if pre FIX5.0)
```
Read more on wiki...
