include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES) -c -o pcap_parser.o pcap_parser.cpp
	g++ $(PCAPPP_LIBS_DIR) -o parser_exec pcap_parser.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm pcap_parser.o
	rm parser_exec
