#include <iostream>
#include <pcap.h>

using namespace std;

void packetHandler(unsigned char *userData, const struct pcap_pkthdr *packetHeader, const unsigned char *packetData)
{
    cout << "Packet captured header: " << packetHeader << endl;
    cout << "Packet captured. Length: " << packetHeader->len << " bytes" << endl;
    // cout << "Packet captured data: " << userData << endl;
}

int main()
{
    pcap_t *pcapHandle;
    char errBuf[PCAP_ERRBUF_SIZE];

    // Open the PCAP file
    pcapHandle = pcap_open_offline("pcap1.pcap", errBuf);
    if (pcapHandle == nullptr)
    {
        cout << "Error opening PCAP file: " << errBuf << endl;
        return 1;
    }

    // Loop over the packets
    int result = pcap_loop(pcapHandle, 0, packetHandler, nullptr);
    if (result != 0)
    {
        cout << "Error occurred during packet processing: " << pcap_geterr(pcapHandle) << endl;
        return 1;
    }

    // Close the PCAP file
    pcap_close(pcapHandle);

    return 0;
}