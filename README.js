# example

Start some nodes.

```
node example_node.js

node example_node.js 9555
```

# implement

Copy the example.

You can `dt.add_object()`, `dt.remove_object()` and listen for `started`, `add`, and `remove` events from `dt.emitter`.

Everything is synchronized on every node in memory.

# security

All messages are encrypted with XOR using the private key entered on every node.

# firewall

Invalid users making too many attempts are blocked by node-ip-ac

https://github.com/andrewhodel/node-ip-ac
