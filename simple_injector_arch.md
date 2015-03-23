```
                                         (if listen enable)       +-----------------------+                      
                                        +-------------------------> listen for connection |                      
                                        |                         +-------------------+---+                      
cmdns from external+----+--+            |                                             |                          
                        +--v------------+-+                                           |                          
                        | bgp main context+--------->control cmnds (to/from)+--+      |                          
                        +--+-------+------+                                    |      |                          
replies to external<----+--+       |                                           |      |                          
                                   |                 +-------+-+  +-----+------v------v-----+                    
                                   v                 |keepalive|  |passive neighbour context|                    
                          cntrl cmnds (to/from)      |         +--+(per neighbour context)  +-------+            
                                   +                 +-------+-+  +-----+-------------------+       |            
                         +---------v+-------------+          |          |                           |            
+--------+--+            |start active connection |          |          |                           |            
| keepalive +------------+(per neighbour context) |          +----+     |                           |            
|           |            +-+-------------+--------+               |     |                           |            
+-----------+------+       |             |                        |     |                           |            
                   |       |             |                       ++-----v---------+           +-----v-----------+
                   |       |             |                       | write goroutine|           |read goroutine   |
                   |       |             |                       |(to neighbour)  |           |(from neighbour) |
                   |       |             |                       +----------------+           +-----------------+
                   |       |             |                                                                       
           +-------v-------v+        +---v------------+                                                          
           | write goroutine|        |read goroutine  |                                                          
           |(to neighbour)  |        |(from neighbour)|                                                          
           +----------------+        +----------------+                                                          

```

#### BGP Main Context
```
/*
   Generic per bgp process data
*/
type BGPContext struct {
        ASN      uint32
        RouterID uint32
        //TODO: rib per afi/safi
        RIBv4         []IPV4_NLRI
        ListenLocal   bool
        Neighbours    []BGPNeighbour
        ToMainContext chan BGPCommand
}
```

responsible for storing all the routes and control per neighbour context (send what to advertise,
report about other connections state (for example during collision detection phase) etc) as 
well as main point of entry to/from external application.
(we are using chans of 
```
/*
used to communicate w/ main bgp process from external apps.
For example:
Cmnd: Advertise
Data: ipv4/ipv6 address/mask
or
Cmnd: Withdraw
Data: ipv4/ipv6 address/mask
*/
type BGPProcessMsg struct {
        Cmnd string
        Data string
}
```
for that purpose.

#### BGP Neighbour context
```
type BGPNeighbourContext struct {
        ToMainContext      chan BGPCommand
        ToNeighbourContext chan BGPCommand
        /* 
           used when we have both inboud and outbound coonnection to the same
           peer and yet do not know which one is going to be threated as collision
        */
        NeighbourAddr string
        ASN           uint32
        RouterID      uint32
        NextHop       string
        fsm           FSM
        //placeholders, not yet implemented
        InboundPolicy  string
        OutboundPolicy string
}
```

responsible for all comunications with external bgp neighbour
(generate bgp msgs, check FSM states etc)

we are using chans of 
```

type BGPCommand struct {
        From     string
        Cmnd     string
        CmndData string
        Route    BGPRoute
        //For anonymous connections
        ResponseChan chan string
        //for passive(when someone connected to us) connection to start
        sockChans SockControlChans
}

```
for that purpose
