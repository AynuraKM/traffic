package main

import (
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket/pcap"
)

var (
	pcapFile string = "capture-Bridge0-May 24 12-50-28.pcapng"
	handle   *pcap.Handle
	err      error
)

func main() {
	udpPackagesCounter := 0
	packagesCounter := 0
	leng := 0

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	bpf, err := handle.NewBPF("udp")
	if err != nil {
		log.Fatal(err)
	}

	for {
		data, ci, err := handle.ReadPacketData()
		switch {
		case err == io.EOF:
			fmt.Println("all packages amount: ", packagesCounter+udpPackagesCounter)
			fmt.Println("udp packages amount: ", udpPackagesCounter)
			av := leng / udpPackagesCounter
			fmt.Println("avarage udp legth: ", av)
			return
		case err != nil:
			log.Fatal(err)
		case bpf.Matches(ci, data):
			udpPackagesCounter++
			length := ci.Length
			leng = leng + length
		default:
			packagesCounter++
			continue
		}
	}

}
