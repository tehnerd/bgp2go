package bgp

const (
	MP_SAFI_UCAST = 1
	MP_SAFI_MCAST = 2
)

/*
 Detail info could be found in RFC4760
*/

type MP_REACH_NLRI_HDR struct {
	AFI      uint16
	SAFI     uint8
	NHLength uint8
	//NEXT_HOP variable length
	/*
		 we also has reserved byte, but we dont
		add it to this struct coz it will be harder for
		us to decode it (we have nh of variable length between
		afi/safi/nhlen and reserved)
	*/
	//RESERVED uint8 (ONE_OCTET)
	//MP-NRLI variable length
}

type MP_UNREACH_NLRI_HDR struct {
	AFI  uint16
	SAFI uint8
	//WithdrawRoutes
}

type MPNRLI_HDR struct {
	Length uint8
	//Prefix variable length
}
