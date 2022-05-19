# example

Run 4 nodes, each on a different port on localhost.

```
node example1.js
node example2.js
node example3.js
node example4.js
```

# implement

Copy the example.

You can `dt.add_object()`, `dt.remove_object()` and listen for `started`, `add`, and `remove` events with `dt.emitter.addListener()`.

Everything is synchronized on every node.

All the work is done in memory.

# security

All messages are encrypted with XOR using the private key entered on every node.

# firewall

Invalid users making too many attempts are blocked by node-ip-ac

https://github.com/andrewhodel/node-ip-ac
