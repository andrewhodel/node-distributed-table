Objects are synchronized across the network using the functions `dt.add_object(object)` and `dt.remove_object(object)` from any node on the network.

Messages sent with `dt.send_message(object)` are sent to all nodes on the network that are online when they reach a connected peer.  They are received in the `message_received` event.

# example

Run 5 nodes, each on a different port on localhost.

```
node example1_master.js
node example2.js
node example3.js
node example4.js
node example5.js
```

# implement

Copy the example.

## functions

`dt.add_object(object)`, `dt.remove_object(object)` and `dt.send_message(object)`.

## events

`'started', function() {}`, `'object_added', function(object) {}`, `'object_removed', function(object) {}` and `'message_received', function(object)` events are created with `dt.emitter.addListener()`.

After the `started` event there is a `object_added` event for each existing object on the network.

# security

All data is encrypted with XOR using the private key entered on every node.

# firewall

Invalid users making too many attempts are blocked by node-ip-ac

https://github.com/andrewhodel/node-ip-ac

# object integrity

Only nodes flagged as master can `add_object()` or `remove_object()`.  Any node can `send_message()`.

This means that an object_diff will accept changes but not make them.

In other words an offline node that has some object that was removed by the master shall be removed when the offline node reconnects.  Objects added by the master while offline shall be added.  Nothing different in the node that was offline will be kept or returned to the dt.

If a segment of nodes goes offline together, when they reconnect to a node that has a path to the master their objects will be synchronized.
