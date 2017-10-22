# ng_sacn
## Change E1.31 sACN packets in transit

Developed for FreeBSD 10.2, this is a netgraph node (https://www.freebsd.org/cgi/man.cgi?netgraph(4)) for modifying E1.31 Lightweight streaming protocol for transport of DMX512 using ACN (aka Streaming ACN/sACN) packets in transit.
It supports both draft (v0.2) and release (E1.31:2009).


## Netgraph Examples
This netgraph node has two hooks "in" and "out", these have obvious uses!

1. Create node between em0 (in) and em1 (out) and name this node "sacn_mangle"
~~~~
ngctl mkpeer en0: sacn lower in
ngctl name en0:lower sacn_mangle
ngctl connect sacn_mangle: em1: out upper
~~~~

2. Block a range of address by setting the range to the value 0, this allows other transmitters for this address range, and priorty; to win HTP. If the range is 512 then the entire packet is dropped.
* Example: Block address 1->100 on universe 1 on node "sacn_mangle"
~~~~
ngctl msg sacn_mangle: set_block_start { universe=1 value=1 }
ngctl msg sacn_mangle: set_block_length { universe=1 value=100 }
~~~~

3. Change priority
* Example: Change the universe priority for universe 1 to 50 on node "sacn_mangle"
~~~~
ngctl msg sacn_mangle: set_priority { universe=1 value=50 }
~~~~

3. Change universe
* Example: Change the universe number for universe 1 to universe 100
~~~~
ngctl msg sacn_mangle: set_universe { universe=1 value=100 }
~~~~



##### Thanks
The basic process of this is based upon the principles of ng_mangle by Dominik Łupiński
http://venus.wsb-nlu.edu.pl/~dlupinsk/ng_mangle/ & https://github.com/ByteFoundryAU/ng_mangle
