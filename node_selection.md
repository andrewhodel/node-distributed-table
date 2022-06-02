### Server init

Each node starts a TCP server that listens on the port specified in `new dt({port: 9999});`.

Any number of nodes can connect to a server.

### Primary client connection routine when disconnected

A node connects to another node to exchange data using the primary client.

When the primary client is disconnected the connection routine starts:

1. find the node with the lowest connection failures
2. find the node that has the lowest latency and less or equal connection failures than the node found in step 1
3. connect to node found in step 2 with the primary client and store the `client_id` from the first message received to be sent with all future messages
4. sends `open` with it's node_id to be tested as `is_self`, validates response or disconnects
5. sends `connected_nodes` to be stored in `fragment_list`
6. begins sending `ping` messages, accepting `pong` messages and maintaining the 20 latest round trip times
7. forwards, sends and receives normal messages per the message type logic

### Clean routine

1. expires `fragment_list` nodes older than 24 hours
2. clears expired message ids
3. initiates tests on distant nodes
4. initiates test on nodes
5. handles reconnects based on latency and `fragment_list` data **

### Distant node logic

`distant_node` messages are exchanged between connected nodes.  Distant nodes are maintained in a list that is different than the list of nodes that a node has.  Nodes are moved from the distant node list to the node list after a successful `test_node()` finishes with them as the subject.

**new client node connected**

* sends a distant node message to every connected client
* sends a distant node message to the server the node is connected to with it's primary client
* sends all the known nodes to the new client

**distant_node sent to server if the distant node does not exist**

`valid_server_message()`

* sends a distant_node message **of itself** to the distant node
* forwards the distant_node message to each connected client node

**distant_node sent to primary client**

`valid_primary_client_message()`

* only adds the distant node if it is does not already exist (this is what keeps it from going through the whole network, distant nodes are not forwarded if received by the primary client, only if received by the server and do not exist).

### test_node()

1. removes any duplicate ip:port pairs that may have been re-added with a different node_id after restart
2. connects to server of remote node
3. sends it's node_id with all messages to be tested as `is_self`
4. sends `connected_nodes` to be stored in `fragment_list`
5. sends 20 `test_ping` messages that each require a `test_pong` response before the next in sequence and stores the data in an ordered set that prunes any data older than the 20th

### reconnects per latency and `fragment_list` data

1. each node compares it's `fragment_list` against non connected nodes and distant nodes
2. if a non connected node is not in `fragment_list`, send the non connected node `{type: 'defragment', fragment_list_length: N}`
3. a 50/50 race condition is prevented because `fragment_list_length` and the count of `fragment_list` is compared on the node receiving `fragment_list_length`.  _If `fragment_list_length` is equal or larger than the count of `fragment_list` then the receiving node reconnects, otherwise the receiving node sends `{type: 'defragment_greater_count'}` and the sending node reconnects_
4. the node that would require the least work to reconnect (in Italics) sends a `distant_node` message of the non connected node via it's primary client, disconnects it's primary client then connects to the non connected node
6. This forces no disconnects that result in a reconnect with fragmentation through all branches of the fragmented segment.  Large networks are possible without the need to know every node.

### `is_self`

type: `is_self` messages allow NAT to work in IPv4 and IPv6 while preventing nodes from having duplicate entries

### node_id

node_ids are generated randomly by a node when a node starts, there is no requirement to maintain a pre deployment list of node_ids

### advanced options

```javascript
// advanced/non configurable options
this.max_test_failures = 5;
this.max_ping_count = 20;
this.clean_interval = 5000;
// if there is a better node to use as the primary, wait this long before disconnecting the existing primary client
this.better_primary_wait = 1000 * 60 * 20;
// a node with a latency lower than this * the primary node latency avg is classified as better
this.better_primary_latency_multiplier = .7;
// wait this long before purging nodes that are
// 1. unreachable
// 2. not updated in the fragment list
this.purge_node_wait = 1000 * 60 * 60;
// retest after a successful test at this interval
this.retest_wait_period = 1000 * 60 * 10;
// do not allow messages with a duplicate message_id more than this often
this.message_duplicate_expire = 1000 * 60 * 5;
// only defrag this often
this.defrag_wait_period = 1000 * 60 * 10;
// debug settings, each shows itself and all those below
// 0	no debugging output
// 1	show nodes
// 2	show messages and what node they are from
this.debug = 0;
```
