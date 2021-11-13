# mp2p - Multicast Peer to Peer

TLDR; this doesn't work on the open internet :(

**Objective:**
"I want to be able to send encrypted data between devices, regardless of NAT and firewalls, and
without an intermediate server"

**Problem:**
 - NAT prevents peer-to-peer communication for ipv4
 - Firewalls prevent peer-to-peer communication for ipv6

**Theory:**
 1. A node can listen on a multicast address
 2. A node can send to any multicast address
 3. Nodes can identify themselves with public keys

**Outcome:**
 - Nodes can communicate by sending to each other's self-chosen multicast address, identifying themselves with their public keys.
 - Nodes can communicate securely by performing diffie hellman key exchanges even though they are using addresses that can be listened to by anyone.

## Proof Of Concept

I wrote two scripts, one behaving like a client, and one behaving like a server.
The client must know the multicast address of the server and the server's public key.
The client can then send the server a signed address declaration, initiate a session where
they perform a diffie hellman key exchange, and then send messages back and forth.

This could be shifted in the network stack to work more similarly to tls, but this is a POC.

## Results

This worked when I was running locally on my laptop, but once I tried to establish communication between my laptop and desktop I found out my router doesn't support multicast packets... I could enable them locally, but that wouldn't beat NAT and therefore doesn't do what I was hoping.

Cheers.
Jack
