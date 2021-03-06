# papr
Packet Analysis Preparation Report - Experimental automated packet capture analysis

This program pre-processes PCAPNG files to extract basic information about the content, including:

* Start and end time of the capture
* Number of frames in the file
* Number of TCP packets missed during capture
* IP route stability
* List TCP, UDP and SCTP service endpoints
* List of DNS servers, DNS error rates and service times
* TCP service endpoint request latency statistics

The program accesses the packet data using a new version of Wireshark Sharkd running in Daemon Mode - see https://gitlab.com/wireshark/wireshark/-/wikis/sharkd-JSON-RPC

## Sharkd Installation

Sharkd is no longer shipped in the binary installation package and this new version of Sharkd is not yet merged into the main Wireshark code.  Therefore, you will need to:

* Build Wireshark from source - see https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
  * Check that it builds OK before going to the next step
* Download sharkd_session.c from https://gitlab.com/credible58/wireshark/-/tree/issue17235 and replace the existing file with this version
  * Build again
  * Start using Sharkd
* Alternative approach
  * Build Wireshark from source in the normal way
  * Modify the Python code here to work with the existing Sharkd API
