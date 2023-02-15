LDLIBS += -lpcap

all: pcap-stat

pcap-stat: pcap-stat.cpp

clean:
	rm -f pcap-stat *.o
