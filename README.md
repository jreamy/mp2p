# mp2p - Multicast Peer to Peer

TLDR; this doesn't work on the open internet :(

**Objective:**
"I want to be able to send encrypted data between devices, regardless of NAT and firewalls, and
without an intermediate server"

**Problem:**
 - NAT prevents peer-to-peer communication for ipv4
 - Firewalls prevent peer-to-peer communication for ipv6

**Premise:**
 1. A node can listen on a multicast address
 2. A node can send to any multicast address
 3. Nodes can identify themselves with public keys

**Theory:**
 - Nodes can communicate by sending to each other's self-chosen multicast address, identifying themselves with their public keys.
 - Nodes can communicate securely by performing diffie hellman key exchanges even though they are using addresses that can be listened to by any other node.

## Proof Of Concept

I wrote two scripts, one behaving like a client, and one behaving like a server.
The client must know the multicast address of the server and the server's public key.
The client can then send the server a signed address declaration, initiate a session where
they perform a diffie hellman key exchange, and then send messages back and forth.

This could be shifted in the network stack to work more similarly to tls, but this is a POC.

Running the server
```go
$ go run examples/server/main.go
my addr: ff1e:ade0:cba9:bb7e:935f:1c03:5b48:1529
my publ: 8135e82d1d513ba277597400cf04061e69b4d2fe5a7cf1c0a2ee2c4940fd76f2
```

The server can also take the `-ipv4` flag and use an ipv4 address. The client can take an ipv4 address and generates its own ipv4 listening address.

Running the client
```go
$ go run examples/client/main.go -addr ff1e:ade0:cba9:bb7e:935f:1c03:5b48:1529 -publ 8135e82d1d513ba277597400cf04061e69b4d2fe5a7cf1c0a2ee2c4940fd76f2
my addr: ff1e:7837:c8de:baf8:88e9:7051:6056:c140
my publ: 5bb97343a7b97e17f8944bf6f7a3cf36946be2928ad6270b14e854de802ee68a
```

## Results

This worked when I was running locally on my laptop, but once I tried to establish communication between my laptop and desktop I found out my router doesn't support multicast packets... I could enable them locally, but that wouldn't beat NAT and therefore doesn't do what I was hoping.

If you try this out and find there's a better configuration that works in more standard cases that'd be cool :)

## Addresses

The ipv6 spec has a range of globally routable, transient ipv6 multicast addresses that are essentially meant for use cases like this (prefix with ff1e). The ipv4 spec doesn't have quite the same intentional setup for self-assigned multicast addresses, so I approximately picked addresses from 224.0.224.0-224.0.249.255 (designated as unassigned by IANA).

Cheers.
Jack
