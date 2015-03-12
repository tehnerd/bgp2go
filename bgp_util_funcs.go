package bgp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	IPV4_TOTAL_OCTETS = 4
	BITS_IN_OCTET     = 8
)

func IPv4ToUint32(ipv4 string) (uint32, error) {
	octets := strings.Split(ipv4, ".")
	if len(octets) != IPV4_TOTAL_OCTETS {
		return 0, errors.New("cant convert ipv4 to string")
	}
	ipv4int := uint32(0)
	for cntr := 0; cntr < IPV4_TOTAL_OCTETS; cntr++ {
		tmpVal, err := strconv.Atoi(octets[cntr])
		if err != nil {
			return 0, errors.New("cant convert ipv4 to string")
		}
		ipv4int += uint32(tmpVal << uint(cntr*BITS_IN_OCTET))
	}
	return ipv4int, nil
}

func Uint32IPv4ToString(ipv4 uint32) string {
	ipv4addr := ""
	octet := 0

	for cntr := 0; cntr < IPV4_TOTAL_OCTETS; cntr++ {
		octet = int((ipv4 >> ((3 - uint(cntr)) * BITS_IN_OCTET)) & 255)
		if cntr == 0 {
			ipv4addr = strconv.Itoa(octet)
		} else {
			ipv4addr = strings.Join([]string{ipv4addr, strconv.Itoa(octet)}, ".")
		}
	}
	return ipv4addr
}

func PrintBgpUpdate(bgpRoute *BGPRoute) {
	OriginString := ""
	switch bgpRoute.ORIGIN {
	case ORIGIN_IGP:
		OriginString = "IGP"
	case ORIGIN_EGP:
		OriginString = "EGP"
	case ORIGIN_INCOMPLETE:
		OriginString = "Incomplete"
	}
	fmt.Printf("content of bgp update message is:\n")
	fmt.Printf("Origin: %v\n", OriginString)
	fmt.Printf("AS_PATH: %v\n", bgpRoute.AS_PATH)
	fmt.Printf("NEXT_HOP: %v\n", bgpRoute.NEXT_HOP)
	fmt.Printf("MED: %v\n", bgpRoute.MULTI_EXIT_DISC)
	fmt.Printf("Local pref: %v\n", bgpRoute.LOCAL_PREF)
	fmt.Printf("is Atomic Aggregate: %v\n", bgpRoute.ATOMIC_AGGR)
	for _, route := range bgpRoute.Routes {
		fmt.Printf("Route: %v/%v\n", Uint32IPv4ToString(route.Prefix), route.Length)
	}

}
