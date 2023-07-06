#include <iostream>
#include <vector>
#include <netinet/in.h>
#include "stdlib.h"
#include "PcapFileDevice.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"

using namespace std;

string getProtocolTypeAsString(pcpp::ProtocolType protocolType);
string printTcpFlags(pcpp::TcpLayer *tcpLayer);
string printTcpOptionType(pcpp::TcpOptionType optionType);
void parseIP(pcpp::Packet parsedPacket);
void parseTCP(pcpp::Packet parsedPacket);

int main(int argc, char *argv[])
{
    int choice = 1;
    // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
    // and create an interface instance that both readers implement
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("pcap1.pcap");

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        cerr << "Cannot determine reader for file type" << endl;
        return 1;
    }

    // open the reader for reading
    if (!reader->open())
    {
        cerr << "Cannot open input.pcap for reading" << endl;
        return 1;
    }

    // the packet container
    pcpp::RawPacket rawPacket;

    // a while loop that will continue as long as there are packets in the input file
    // matching the BPF filter
    while (reader->getNextPacket(rawPacket) && choice)
    {
        if (!reader->getNextPacket(rawPacket))
        {
            cerr << "Couldn't read the first packet in the file" << endl;
            return 1;
        }

        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        vector<string> protocols{"Ethernet", "IPv4", "TCP", "HTTP"};

        // first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
        for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
        {
            int flag = 0;
            string protocol = getProtocolTypeAsString(curLayer->getProtocol());
            for (auto it : protocols)
            {
                if (protocol == it)
                {
                    flag = 1;
                }
            }
            if (flag)
            {
                cout << "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; " // get layer type
                     << "Total data: " << curLayer->getDataLen() << " [bytes]; "                   // get total length of the layer
                     << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; "                 // get the header length of the layer
                     << "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]"         // get the payload length of the layer (equals total length minus header length)
                     << endl;
                if (protocol == "IPv4")
                {
                    parseIP(parsedPacket);
                }
                if (protocol == "TCP")
                {
                    parseTCP(parsedPacket);
                }
            }
        }
        cout << "\n Do you want to parse the next packet ? (1-Yes/0-No)";
        cin >> choice;
        cout << "\n \n";
    }
}

string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::TCP:
        return "TCP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}

string printTcpFlags(pcpp::TcpLayer *tcpLayer)
{
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";

    return result;
}

string printTcpOptionType(pcpp::TcpOptionType optionType)
{
    switch (optionType)
    {
    case pcpp::PCPP_TCPOPT_NOP:
        return "NOP";
    case pcpp::PCPP_TCPOPT_TIMESTAMP:
        return "Timestamp";
    default:
        return "Other";
    }
}

void parseIP(pcpp::Packet parsedPacket)
{
    // let's get the IPv4 layer
    cout << "\n \n \t \t**** PARSING IP ****";
    pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer == NULL)
    {
        cerr << "Something went wrong, couldn't find IPv4 layer" << endl;
        return;
    }
    // print source and dest IP addresses, IP ID and TTL
    cout << endl
         << "Source IP address: " << ipLayer->getSrcIPAddress() << endl
         << "Destination IP address: " << ipLayer->getDstIPAddress() << endl
         << "IP ID: 0x" << hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << endl
         << "TTL: " << dec << (int)ipLayer->getIPv4Header()->timeToLive << endl;
}

void parseTCP(pcpp::Packet parsedPacket)
{
    cout << "\n \n \t \t**** PARSING TCP ****";
    // let's get the TCP layer
    pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer == NULL)
    {
        cerr << "Something went wrong, couldn't find TCP layer" << endl;
        return;
    }
    // print TCP source and dest ports, window size, and the TCP flags that are set in this layer
    cout << endl
         << "Source TCP port: " << tcpLayer->getSrcPort() << endl
         << "Destination TCP port: " << tcpLayer->getDstPort() << endl
         << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << endl
         << "TCP flags: " << printTcpFlags(tcpLayer) << endl;

    cout << "TCP options: ";
    for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
    {
        cout << printTcpOptionType(tcpOption.getTcpOptionType()) << " ";
    }
    cout << endl;
}