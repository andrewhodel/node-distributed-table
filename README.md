Objects are synchronized across the network using the functions `dt.add_object(object)` and `dt.remove_object(object)` from a master node.

Messages sent with `dt.send_message(object)` are sent to all nodes on the network that are online when they reach a connected peer.  They are received in the `message_received` event.

IPv4 and IPv6 are supported.

# install

`git clone --recursive https://github.com/andrewhodel/node-distributed-table`

# example

Run 5 nodes, each on a different port on localhost.

```
node example1_master.js
node example2.js
node example3.js
node example4.js
node example5.js
```

# load test example

Run 2 nodes, each on a different port on localhost.

Each writes the output to a log file in the current working directory that is truncated and stores the newest data.

```
node example1_master_load_test.js > /dev/null 2>&1 &
node example2_load_test.js > /dev/null 2>&1 &
```

Read the files periodically, if the total object count stops changing 3 iterations in a row the process exits and the log file remains with the connected node data.

Each log file will be no larger than 10MB.

```
cat example1_master_load_test.log
cat example2_load_test.log
```

# implement

Copy the example.

## functions

`dt.add_object(object)`, `dt.remove_object(object)` and `dt.send_message(object)`.

`dt.add_object(object)` and `dt.remove_object(object)` can emit an `error` event from `dt.emitter`.

## events

`'started', function() {}`, `'object_added', function(object) {}`, `'object_removed', function(object) {}` and `'message_received', function(object)` and `'error', function(error_string, origin, object)` events are created with `dt.emitter.addListener()`.

After the `started` event there is a `object_added` event for each existing object on the network.

# master node and object integrity

Only nodes flagged as master can `add_object()` or `remove_object()`.  Any node can `send_message()`.

Non master nodes will accept changes and relay changes but not be allowed to create changes with `add_object()` or `remove_object()`.

A node processing a diff will modify itself and **shall remove any objects that are not in the diff from itself before forwarding objects**.  This is internally known as a `object_hashes` message.

In other words an offline node that has some object that was removed in the dt by the master shall be removed when the offline node reconnects.  Objects added to the dt by the master while offline shall be added.  Nothing different in the node that was offline will be kept or returned to the dt.

If a segment of nodes goes offline together, when they reconnect to a node that has a path to the master their objects will be synchronized.

A master node does not need to open ports or listen for traffic, it can be a master node behind a firewall or NAT.

# running without a master

No node is required to be a master in a dt network, but the nodes can only send and receive message objects.

# security

All data is encrypted with XOR using the private key entered on every node.

# firewall

Invalid users making too many attempts are blocked by node-ip-ac

https://github.com/andrewhodel/node-ip-ac

# example 1. make a CDN

Use the master node to load content via `add_object()`.

Each HTTPS server running as a dt node can send it's public IP address, geographic location and online status with `send_message()` at regular intervals to a webserver that redirects with `HTTP 301`.

Any updates to the content from the master automatically update all nodes.

# example 2. DNS record publishing/zone transfers

Any number of DNS servers can be replicated by being nodes of a dt network by using master nodes to add or remove records.

# example 3. file synchronization and backups

Maintain any number of dt nodes on the Internet and start your master node to replicate and store all of your files on every node.

Store the file data in dt objects as base64 strings, compress it if you need to.

# example 4. world valid DNS lookups

Even DKIM could be spoofed if you modified the DNS response of the public key's DNS record.  Use dt to create a DNS resolver that resolves from many locations and validates that the results have not been modified using dt messages.

Ensure that MX records are the same at every location before sending an email.

# donate

## Bitcoin
BTC 39AXGv2up1Yk5QNeLHfQra815jaYv9HcJk

## Credit Card
[![Paypal Donation](/img/paypal_donate_button.gif "Paypal Donation")](https://www.paypal.com/donate/?hosted_button_id=5XCWCGPC2FBU6)

## Paypal by QR Code
![Paypal QR Donation](/img/paypal_donate_qr.png "Paypal QR Donation")
