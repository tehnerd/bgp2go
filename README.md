## Golang's bgp implementation (control plane only)

### What is it?
 This is a package for golang which implements BGP's (rfc 4271 etc) feature sets
 
### Intendent usecases:
 The package must allow to participate in bgp exchange. Main goals is to be able to inject locally generated routes to 
 the bgp domain (for example from the SLBs; i've started this project as a side package, for my keepalived project) as well as
 to be able to recieve and process bgp msgs from the peers (for example to be used in some kind of analytic tool)
 
### Where it's now?
 Right now i'm trying to implement minimal functionals to be able to exchange ipv4 bgp routes. (we already can parse almost
 any msgs from the peers)
 
### Where it's going to be in a... ?
#### Nearest future
 The second musthave feature (the first one is working ipv4 implementation) is ipv6
#### Future
 I want for this package to be able to parse and/or generate
'''
IPv4 unicast routes
IPv4 labeled unicast routes
IPv6 unicast routes
IPv6 labeled unicast routes
(and maybe; not yet sure; flowspec)
'''
And to be able to parse routes for the rest of the know mp-bgp's families (vpns vpls etc etc etc)

### Why i dont use exabgp instead?
 Because i want to have golang's implementation and it's interesting for me to write this 
 
### how active this project will be?
 as i can see it right now, it will be my pet project (where i'm going to contribute @ after work hours), so dont expect 
 that this is going to be fulltime project (well at least while i'm working alone @ in)
