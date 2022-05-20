/*
MIT License

Copyright (c) 2022 Andrew Hodel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

'use strict';

var crypto = require('crypto');
var net = require('net');
var events = require('events');
var ipac = require('./node-ip-ac/node-ip-ac.js');

var dt = function(config) {

	// config {}
	// port			number		port to listen on
	// key			string		key to encrypt all traffic, common to all nodes
	// nodes		[string]	list of IPv4 and IPv6 addresses of some public nodes
	// timeout		number		timeout in milliseconds
	// ping_interval	number		ping interval in milliseconds

	var init_error = [];
	if (typeof(config.port) !== 'number') {
		init_error.push('new dt(config), config.port must be a number with the udp port to listen on');
	}
	if (typeof(config.key) !== 'string') {
		init_error.push('new dt(config), config.key must be a string of the key to encrypt all traffic with that is common to all nodes');
	}
	if (typeof(config.nodes) !== 'object') {
		init_error.push('new dt(config), config.nodes must be an array of strings of IPv6 and IPv4 address:port of the nodes');
	}
	if (typeof(config.timeout) !== 'number') {
		config.timeout = 7000;
	}
	if (typeof(config.ping_interval) !== 'number') {
		config.ping_interval = 2000;
	}

	if (init_error.length > 0) {
		console.error(init_error);
		process.exit(1)
	}

	// configurable options
	this.port = Number(config.port);
	this.key = Buffer.from(config.key);
	this.timeout = Number(config.timeout);
	this.ping_interval = Number(config.ping_interval);

	// storage objects
	this.nodes = [];
	this.distant_nodes = [];
	this.objects = [];

	// advanced/non configurable options
	this.max_test_failures = 5;
	this.max_ping_count = 20;
	this.clean_interval = 5000;

	var c = 0;
	while (c < config.nodes.length) {
		// build the nodes objects for the initial nodes
		// initial nodes are servers that this node can connect to
		var ip_port = config.nodes[c].split(':');

		if (ip_port.length !== 2) {
			console.error('node is missing IP and port', config.nodes[c]);
			process.exit(1);
		}

		this.nodes.push({ip: ip_port[0], port: Number(ip_port[1]), is_self: false, type: 'initial', primary_connection_failures: 0, node_id: null, rtt: -1, rtt_array: [], connected_as_primary: false, test_status: 'pending', test_failures: 0})

		c++;

	}

	// to prevent the node from connecting to itself
	this.node_id = crypto.randomUUID();

	this.ip_ac = ipac.init();

	console.log('creating new dt node', this.port, this.node_id);

	this.server = net.createServer((conn) => {
		// 'connection' listener.
		// this is a new client

		if (ipac.test_ip_allowed(this.ip_ac, conn.remoteAddress) === false) {
			// this IP address has been blocked by node-ip-ac
			conn.end();
			return;
		}

		console.log('client connected', conn.remoteAddress);

		// add the client id
		// because the client end event may happen after a reconnect
		conn.client_id = crypto.randomUUID();

		var data = Buffer.alloc(0);
		var data_len = 0;

		var test_all_data = function() {

			//console.log('test_all_data()', data_len, data.length);
			if (data_len <= data.length) {

				// decrypt the data_len
				var decrypted = this.dt_object.decrypt(data.subarray(0, data_len));
				//console.log('decrypted', decrypted.length, decrypted.toString());

				if (data.length > data_len) {

					// there are multiple messages
					data_len = data.readUInt32BE(0);
					data = data.subarray(4, data.length);

					// continue parsing
					test_all_data();

				} else {
					// reset data and data_len
					data = Buffer.alloc(0);
					data_len = 0;
				}

				try {

					// decrypted is a valid message
					var vm = JSON.parse(decrypted);
					this.dt_object.valid_server_message(conn, vm);

					// type open is the first message
					if (vm.type === 'open') {

						// this is an authorized connection
						ipac.modify_auth(this.dt_object.ip_ac, true, conn.remoteAddress);

						// send object_diff
						var o_diff = [];
						var n = 0;
						while (n < this.dt_object.objects.length) {
							// add the sha256 checksum to the array
							o_diff.push(this.dt_object.objects[n][0]);
							n++;
						}
						this.dt_object.server_send(conn, {type: 'object_diff', object_diff: o_diff});

					}

				} catch (err) {
					console.error('error in server with a client authorization', err);
					// if the decrypted message does not parse into JSON
					// this is an invalid connection
					ipac.modify_auth(this.dt_object.ip_ac, undefined, conn.remoteAddress);
					conn.end();
				}

				return;

			}

			// not finished
			return;

		}.bind({dt_object: this});

		conn.on('data', (chunk) => {

			if (data.length === 0) {
				// first chunk

				// read length
				data_len = chunk.readUInt32BE(0);

				//console.log('first chunk, data length', data_len);

				// add to data without length
				data = chunk.subarray(4);

				test_all_data();

			} else if (data_len > data.length) {

				// continue to read through data_len
				data = Buffer.concat([data, chunk]);

				test_all_data();

			} else if (data_len === data.length) {

				test_all_data();

			} else {

				// disconnect/reconnect
				// data was manipulated or lost in transit
				console.error('server data recieve error', chunk.toString(), data.toString());
				conn.end();

			}

		});

		conn.on('end', () => {

			console.log('client disconnected');

		});

		//conn.write('hello\r\n');

		//conn.pipe(conn);

	});

	this.server.on('error', (err) => {
		console.error(err);
		process.exit(1);
	});

	this.server.listen(this.port, () => {
		console.log('server bound', this.port);

		// connect to a node
		this.connect();

		// start clean routine
		this.clean();

		this.emitter.emit('started');

	});

}

dt.prototype.connect = function() {

	// short delay
	var start = Date.now();

	var waiter = setInterval(function() {

		if (Date.now() - start < 1000 * 3) {
			// waiting
			return;
		}

		clearInterval(waiter);

		// connect to a node
		console.log('\ndt.connect() total nodes', this.dt_object.nodes.length);

		// solve what node to connect to
		var lowest_primary_connection_failures = 0;
		this.dt_object.connect_node = {};

		var c = 0;
		while (c < this.dt_object.nodes.length) {

			var n = this.dt_object.nodes[c];

			if (n.is_self === true) {
				// do not attempt connection to self
				c++;
				continue;
			}

			if (n.type === 'client') {
				if (n.conn) {
					// do not attempt connection to client nodes that are already connected
					// a connection object means the node is connected
					c++;
					continue;
				}
				//console.log('attempting connection to client because it is not connected as a client');
			}

			if (n.primary_connection_failures <= lowest_primary_connection_failures || Object.keys(this.dt_object.connect_node).length === 0) {
				// finding the node with the lowest primary_connection_failures
				// connect to it
				this.dt_object.connect_node = n;
				lowest_primary_connection_failures = n.primary_connection_failures;
			}

			c++;

		}

		if (Object.keys(this.dt_object.connect_node).length === 0) {
			// this node has no nodes to connect to
			// it should stay on to allow nodes to connect to it
			console.log('no nodes ready for connection');

			// try again
			this.dt_object.connect();
			return;
		}

		console.log('node with lowest primary connection failures', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

		// ping the server
		var ping;

		this.dt_object.client = net.connect({port: this.dt_object.connect_node.port, host: this.dt_object.connect_node.ip, keepAlive: true}, () => {
			// 'connect' listener.
			console.log('primary client connected to', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

			// set the start time of this connection
			this.dt_object.connect_node.primary_connection_start = Date.now();

			// send node_id
			this.dt_object.client_send({type: 'open', node_id: this.dt_object.node_id, listening_port: this.dt_object.port});

			// send object_diff
			var o_diff = [];
			var n = 0;
			while (n < this.dt_object.objects.length) {
				// add the sha256 checksum to the array
				o_diff.push(this.dt_object.objects[n][0]);
				n++;
			}
			this.dt_object.client_send({type: 'object_diff', object_diff: o_diff});

			// ping the server
			// and send the previous rtt
			ping = setInterval(function() {

				this.dt_object.client_send({type: 'ping', node_id: this.dt_object.node_id, ts: Date.now(), previous_rtt: this.dt_object.connect_node.rtt});

			}.bind({dt_object: this.dt_object}), this.dt_object.ping_interval);

			// send the initial nodes as type: distant node each time this node connects as a client
			// to each connected client
			var c = 0;
			while (c < this.dt_object.nodes.length) {

				var n = this.dt_object.nodes[c];
				if (n.type === 'initial') {

					var l = 0;
					while (l < this.dt_object.nodes.length) {
						if (this.dt_object.nodes[l].type === 'client') {
							if (this.dt_object.nodes[l].conn) {
								this.dt_object.server_send(this.dt_object.nodes[l].conn, {type: 'distant_node', ip: n.ip, port: n.port, node_id: n.node_id});
							}
						}
						l++;
					}

				}

				c++;
			}

		});

		// set client timeout of the socket
		this.dt_object.client.setTimeout(this.dt_object.timeout);

		var data = Buffer.alloc(0);
		var data_len = 0;

		var test_all_data = function() {

			//console.log('test_all_data()', data_len, data.length);
			if (data_len <= data.length) {

				// decrypt the data_len
				var decrypted = this.dt_object.decrypt(data.subarray(0, data_len));
				//console.log('decrypted', decrypted.length, decrypted.toString());

				if (data.length > data_len) {

					// there are multiple messages
					data_len = data.readUInt32BE(0);
					data = data.subarray(4, data.length);

					// continue parsing
					test_all_data();

				} else {
					// reset data and data_len
					data = Buffer.alloc(0);
					data_len = 0;
				}

				try {
					// decrypted is a valid message
					this.dt_object.valid_client_message(JSON.parse(decrypted));
				} catch (err) {
					console.error('error in primary client authorization to server', err);
				}

				return;

			}

			// not finished
			return;

		}.bind({dt_object: this.dt_object});

		this.dt_object.client.on('data', (chunk) => {

			if (data.length === 0) {
				// first chunk

				// read length
				data_len = chunk.readUInt32BE(0);

				//console.log('first chunk, data length', data_len);

				// add to data without length
				data = chunk.subarray(4);

				test_all_data();

			} else if (data_len > data.length) {

				// continue to read through data_len
				data = Buffer.concat([data, chunk]);

				test_all_data();

			} else if (data_len === data.length) {

				test_all_data();

			} else {

				// disconnect/reconnect
				// data was manipulated or lost in transit
				console.error('client data recieve error', chunk.toString(), data.toString());
				this.dt_object.client.end();

			}

		});

		this.dt_object.client.on('end', () => {

			// stop pinging
			clearInterval(ping);

			this.dt_object.connect_node.connected_as_primary = false;

			console.log('node disconnected from server node', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

			// reconnect to the network
			this.dt_object.connect();

		});

		this.dt_object.client.on('timeout', () => {

			console.error('timeout connecting to node', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

			this.dt_object.connect_node.connected_as_primary = false;

			// a connection timeout is a failure
			this.dt_object.connect_node.primary_connection_failures++;

			// reconnect to the network
			this.dt_object.connect();

		});

		this.dt_object.client.on('error', (err) => {

			console.error('error connecting to node', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect.node_id, err.toString());

			this.dt_object.connect_node.connected_as_primary = false;

			// a connection error is a failure
			this.dt_object.connect_node.primary_connection_failures++;

			// reconnect to the network
			this.dt_object.connect();

		});

	}.bind({dt_object: this}), 200);

}

dt.prototype.rtt_avg = function(r) {

	if (r === undefined) {
		return -1;
	}

	var sum = 0;
	var c = 0;
	while (c < r.length) {
		sum += r[c];
		c++;
	}

	return sum / c;

}

dt.prototype.test_node = function(node, is_distant_node=false) {

	//console.log('testing node', node);

	if (is_distant_node === true) {

		// make sure there is only one unique ip:port pair per distant node
		var remove = false;
		var c = 0;
		while (c < this.distant_nodes.length) {
			var n = this.distant_nodes[c];

			if (node.ip === n.ip && node.port === n.port) {

				// same ip and port
				if (node.node_id !== n.node_id) {
					// this is a different node with the same ip and port
					// remove this one and do not run the test
					// the other one may be running a test and this one is not
					remove = true;
					break;
				}
			}

			c++;

		}

		if (remove === true) {
			//console.log('removing distant_node duplicate, not testing', node);

			var l = 0;
			while (l < this.distant_nodes.length) {
				var r = this.distant_nodes[l];
				if (node.node_id === r.node_id) {
					this.distant_nodes.splice(l, 1);
					break;
				}
				l++;
			}

			return;
		}

	}

	node.test_start = Date.now();
	node.test_status = 'current';

	// distant node ping
	var ping;
	var recieved_pings = 0;

	var client = net.connect({port: node.port, host: node.ip, keepAlive: true}, function() {
		// 'connect' listener.
		console.log('connected to node to test latency', node.ip, node.port);

		// ping the server
		// and send the previous rtt
		ping = setInterval(function() {

			// send with this node's node_id
			this.dt_object.client_send({type: 'distant_node_ping', node_id: this.dt_object.node_id, ts: Date.now(), previous_rtt: node.rtt}, client);

		}.bind({dt_object: this.dt_object}), this.dt_object.ping_interval);

	}.bind({dt_object: this}));

	// set client timeout of the socket
	client.setTimeout(this.timeout);

	var data = Buffer.alloc(0);
	var data_len = 0;

	var test_all_data = function() {

		//console.log('test_all_data()', data_len, data.length);
		if (data_len <= data.length) {

			// decrypt the data_len
			var decrypted = this.dt_object.decrypt(data.subarray(0, data_len));
			//console.log('decrypted', decrypted.length, decrypted.toString());

			if (data.length > data_len) {

				// there are multiple messages
				data_len = data.readUInt32BE(0);
				data = data.subarray(4, data.length);

				// continue parsing
				test_all_data();

			} else {
				// reset data and data_len
				data = Buffer.alloc(0);
				data_len = 0;
			}

			try {
				// decrypted is a valid message
				var j = JSON.parse(decrypted);

				if (j.type === 'is_self') {

					node.node_id = j.node_id;
					node.is_self = true;
					node.test_status = 'is_self'
					client.end();

				} if (j.type === 'distant_node_pong') {

					// set the node_id as it may have originated from a node storing it as initial that has yet to connect
					node.node_id = j.node_id;

					// calculate the rtt between this node and the server it is connected to
					var rtt = Date.now() - j.ts;

					node.rtt = rtt;
					//console.log(rtt + 'ms RTT to server');

					node.rtt_array.push(rtt);

					if (node.rtt_array.length > this.dt_object.max_ping_count) {
						// keep the latest dt.max_ping_count by removing the first
						node.rtt_array.shift();
					}

					recieved_pings++;
					if (recieved_pings >= this.dt_object.max_ping_count) {
						// test success at dt.max_ping_count pings
						client.end();
						node.test_status = 'success';
						node.test_failures = 0;

						console.log('node test success, avg rtt', this.dt_object.rtt_avg(node.rtt_array));

						if (is_distant_node === true) {

							// remove any distant_node entries that have the same ip and port
							// as the node_id may have changed
							var c = this.dt_object.distant_nodes.length-1;
							while (c >= 0) {
								var n = this.dt_object.distant_nodes[c];
								if (n.node_id === node.node_id) {
									// this is the same entry
								} else {
									if (n.ip === node.ip && n.port === node.port) {
										// this is another entry with the same ip and port but a different node_id
										// remove it because only one node can run on a single IP and port
										this.dt_object.distant_nodes.splice(c, 1);
									}
								}
								c--;
							}

						}

					}

				}

			} catch (err) {
				console.error('error with node test', err);
				client.end();
				node.test_status = 'failed';
				node.test_failures++;
			}

			return;

		}

		// not finished
		return;

	}.bind({dt_object: this});

	client.on('data', (chunk) => {

		if (data.length === 0) {
			// first chunk

			// read length
			data_len = chunk.readUInt32BE(0);

			//console.log('first chunk, data length', data_len);

			// add to data without length
			data = chunk.subarray(4);

			test_all_data();

		} else if (data_len > data.length) {

			// continue to read through data_len
			data = Buffer.concat([data, chunk]);

			test_all_data();

		} else if (data_len === data.length) {

			test_all_data();

		} else {

			// disconnect/reconnect
			// data was manipulated or lost in transit
			console.error('data recieve error in node test', chunk.toString(), data.toString());
			client.end();
			node.test_status = 'failed';
			node.test_failures++;

		}

	});

	client.on('end', () => {

		// stop pinging
		clearInterval(ping);

		console.log('disconnected from node in node test', node.ip, node.port, node.node_id);

	});

	client.on('timeout', () => {

		console.error('timeout connecting to node in node test', node.ip, node.port, node.node_id);
		node.test_status = 'failed';
		node.test_failures++;

	});

	client.on('error', (err) => {

		console.error('error connecting to node in node test', node.ip, node.port, node.node_id, err.toString());
		node.test_status = 'failed';
		node.test_failures++;

	});

}

dt.prototype.clean_remote_address = function(r) {

	// socket.remoteAddress often has ::ffff: at the start and should not

	if (r.indexOf('::ffff:') === 0) {
		r = r.substring(7);
	}

	return r;

}

dt.prototype.clean = function() {

	setInterval(function() {

		// needs connection selection routine
		// based on long >5m intervals

		console.log('\nsorting hosts by latency');

		// test latency and expiration of nodes and distant nodes
		// remember that the node_id changes each time the node is restarted

		console.log('\tdistant nodes');
		var c = 0;
		while (c < this.dt_object.distant_nodes.length) {
			var n = this.dt_object.distant_nodes[c];
			console.log('connected_as_primary: ' + n.connected_as_primary + ', type: ' + n.type + ', test_failures: ' + n.test_failures + ', test_status: ' + n.test_status + ', ' + n.ip + ':' + n.port + ', node_id: ' + n.node_id + ', primary_connection_failures: ' + n.primary_connection_failures + ', last_primary_connection: ' + ((Date.now() - n.last_primary_connection) / 1000) + 's ago, test_start: ' + ((Date.now() - n.test_start) / 1000) + 's ago, rtt_array(' + n.rtt_array.length + '): ' + this.dt_object.rtt_avg(n.rtt_array) + 'ms AVG RTT, rtt: ' + n.rtt + 'ms RTT');

			if (n.test_status === 'pending') {

				// start a latency test on this distant node
				this.dt_object.test_node(n, true);

			} else if (n.test_status === 'failed') {

				if (n.test_failures <= this.dt_object.max_test_failures) {
					// retest
					this.dt_object.test_node(n, true);
				}

			}

			c++;
		}

		console.log('\tnodes');
		var l = 0;
		while (l < this.dt_object.nodes.length) {
			var n = this.dt_object.nodes[l];
			console.log('connected_as_primary: ' + n.connected_as_primary + ', type: ' + n.type + ', test_failures: ' + n.test_failures + ', test_status: ' + n.test_status + ', ' + n.ip + ':' + n.port + ', node_id: ' + n.node_id + ', primary_connection_failures: ' + n.primary_connection_failures + ', last_primary_connection: ' + ((Date.now() - n.last_primary_connection) / 1000) + 's ago, test_start: ' + ((Date.now() - n.test_start) / 1000) + 's ago, rtt_array(' + n.rtt_array.length + '): ' + this.dt_object.rtt_avg(n.rtt_array) + 'ms AVG RTT, rtt: ' + n.rtt + 'ms RTT');

			if (n.connected_as_primary === false) {
				// this is not the node that is connected via the primary client

				if (n.test_status === 'pending') {

					// start a latency test on this node
					this.dt_object.test_node(n);

				} else if (n.test_status === 'failed') {

					if (n.test_failures <= 5) {
						// retest
						this.dt_object.test_node(n);
					}

				}

			}

			l++;
		}

		// to ensure direct connectivity to the node with the lowest latency
		// examine node rtt times and reconnect if
		//	primary_connection_start of node connected_as_primary is > 20 minutes ago
		//	avg rtt is .7 of node connected_as_primary

		// reset test_status === success to test_status: pending every 10m + random(5m)
		// reset test_status === failed and test_failures >= dt.max_test_failures to test_status: pending every 10m + random(5m)

		// send a long object to test
		/*
		var s = '';
		while (l < 50000) {
			s += 'a';
			l++;
		}
		this.dt_object.server_send(this.dt_object.conn, {type: 'test', node_id: this.dt_object.node_id, test: s});
		*/

	}.bind({dt_object: this}), this.clean_interval);

}

dt.prototype.server_send = function(conn, j) {

	// expects a JSON object

	// encrypt the JSON object string
	var jsb = this.encrypt(Buffer.from(JSON.stringify(j)));

	//console.log('server_send() length', jsb.length);

	// write the length
	var b = Buffer.alloc(4);
	b.writeUInt32BE(jsb.length, 0);

	b = Buffer.concat([b, jsb]);

	if (conn) {
		conn.write(b);
	}

}

dt.prototype.client_send = function(j, client=null) {

	// send to a server
	// as the client

	// expects a JSON object

	// encrypt the JSON object string
	var jsb = this.encrypt(Buffer.from(JSON.stringify(j)));

	//console.log('client_send() length', jsb.length);

	// write the length
	var b = Buffer.alloc(4);
	b.writeUInt32BE(jsb.length, 0);

	b = Buffer.concat([b, jsb]);

	if (client !== null) {
		// this is to a distant node
		client.write(b);
	} else if (this.client) {
		// send as the primary client
		this.client.write(b);
	}

}

dt.prototype.decrypt = function(b) {

	var c = 0;
	var key_position = 0;
	while (c < b.length) {

		if (key_position > this.key.length - 1) {
			key_position = 0;
		}

		b[c] = b[c] ^ this.key[key_position];
		c++;
		key_position++;

	}

	return b;

}

dt.prototype.encrypt = function(b) {

	var c = 0;
	var key_position = 0;
	while (c < b.length) {

		if (key_position > this.key.length - 1) {
			key_position = 0;
		}

		b[c] = this.key[key_position] ^ b[c];
		c++;
		key_position++;

	}

	return b;

}

dt.prototype.valid_server_message = function(conn, j) {

	// j is a valid message object
	// that was sent to this server
	//console.log('valid message to server', j);

	if (j.node_id === this.node_id) {
		// tell the client that it connected to itself
		this.server_send(conn, {type: 'is_self', node_id: this.node_id});
	} else if (j.type === 'distant_node_ping') {
		// respond with pong
		this.server_send(conn, {type: 'distant_node_pong', node_id: this.node_id, ts: j.ts});
	} else if (j.type === 'ping') {
		// respond with pong
		this.server_send(conn, {type: 'pong', node_id: this.node_id, ts: j.ts});

		// set the last connected date
		// set the rtt between this server and the client from j.previous_rtt
		// this is calculated by the client, and all nodes in the network are trusted by using the same key
		var c = 0;
		while (c < this.nodes.length) {
			if (this.nodes[c].node_id === j.node_id) {
				// set primary client node values
				this.nodes[c].rtt = j.previous_rtt;
				this.nodes[c].last_primary_connection = Date.now();
				this.nodes[c].connected_as_primary = true;

				this.nodes[c].rtt_array.push(j.previous_rtt);
				if (this.nodes[c].rtt_array.length > this.max_ping_count) {
					// keep the latest dt.max_ping_count by removing the first
					this.nodes[c].rtt_array.shift();
				}

				break;
			}
			c++;
		}

	} else if (j.type === 'open') {

		// this is a directly connected node that is a client of this server

		// add the node_id to the conn object
		conn.node_id = j.node_id;

		var updated = false;
		var c = 0;
		while (c < this.nodes.length) {

			if (this.nodes[c].node_id === j.node_id) {
				// update the node in this.nodes
				this.nodes[c] = {ip: this.clean_remote_address(conn.remoteAddress), port: j.listening_port, is_self: false, type: 'client', primary_connection_failures: 0, node_id: j.node_id, client_id: conn.client_id, conn: conn, last_primary_connection: Date.now(), rtt: -1, rtt_array: []};
				updated = true;
			} else if (this.nodes[c].type === 'client') {
				if (this.nodes[c].conn) {
					// a connection object means the node is connected
					// tell this client node that a client connected
					//console.log('sending distant_node to a client');
					this.server_send(this.nodes[c].conn, {type: 'distant_node', ip: this.clean_remote_address(conn.remoteAddress), port: j.listening_port, node_id: j.node_id});
				}
			}
			c++;
		}

		// tell the server that a distant_node that is a client connected 
		//console.log('sending distant_node to the server');
		this.client_send({type: 'distant_node', ip: this.clean_remote_address(conn.remoteAddress), port: j.listening_port, node_id: j.node_id});

		if (updated === false) {
			// add or the node to this.nodes
			this.nodes.push({ip: this.clean_remote_address(conn.remoteAddress), port: j.listening_port, is_self: false, type: 'client', primary_connection_failures: 0, node_id: j.node_id, client_id: conn.client_id, conn: conn, last_primary_connection: Date.now(), rtt: -1, rtt_array: [], connected_as_primary: false, test_status: 'pending', test_failures: 0})
		}

	} else if (j.type === 'distant_node') {
		// the client node sent a distant node

		var exists = false;
		var l = 0;
		while (l < this.distant_nodes.length) {

			if (this.distant_nodes[l].node_id === j.node_id) {
				exists = true;
				this.distant_nodes[l].ts = Date.now();
				break;
			}

			l++;

		}

		if (exists === false) {
			// there is no existing path to this distant node

			// add to this.distant_nodes that are tested for improved connection quality
			// and may be added as nodes
			this.distant_nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, ts: Date.now(), test_status: 'pending', rtt: -1, rtt_array: [], test_failures: 0});

			// the distant node may need to know of this node
			// send a distant_node message of this node to the client
			// with ip: null so that the client knows to use socket.remoteAddress
			// there is no requirement to do this more than once
			this.server_send(conn, {type: 'distant_node', ip: null, port: this.port, node_id: this.node_id});

			// send through to all the connected clients
			var c = 0;
			while (c < this.nodes.length) {
				// except the one that sent it
				if (this.nodes[c].type === 'client' && this.nodes[c].node_id !== conn.node_id) {
					if (this.nodes[c].conn) {
						//console.log('relaying distant_node to a client');
						this.server_send(this.nodes[c].conn, {type: 'distant_node', ip: j.ip, port: j.port, node_id: j.node_id});
					}
				}
				c++;
			}

		}

	} else if (j.type === 'add_object') {

		// the client node sent an object

		// get the hash
		var sha256_hash = this.object_sha256_hash(j.object);

		// make sure it does not already exist
		var c = 0;
		while (c < this.objects.length) {
			var obj = this.objects[c];
			if (obj[0] === sha256_hash) {
				console.log('client sent duplicate object in add_object', j.object);
				return;
			}
			c++;
		}

		// this.objects is an array of [sha265_hash, object]
		var o = [sha256_hash, j.object];
		this.objects.push(o);

		console.log('client sent add_object to this node', o, this.objects.length);

		// send the object to the server
		this.client_send({type: 'add_object', object: j.object});

		// send to all the connected clients except this one
		var c = 0;
		while (c < this.nodes.length) {
			// except the one that sent it
			if (this.nodes[c].type === 'client' && this.nodes[c].node_id !== conn.node_id) {
				if (this.nodes[c].conn) {
					this.server_send(this.nodes[c].conn, {type: 'add_object', object: j.object});
				}
			}
			c++;
		}

	} else if (j.type === 'object_diff') {

		// a client node sent it's list of object sha256 checksums/hashes
		console.log('client node sent object_diff', j, this.objects);

	}

}

dt.prototype.valid_client_message = function(j) {

	// j is a valid message object
	// that was sent to the client
	//console.log('valid client message', j);

	if (j.type === 'is_self') {
		// the client connected to itself
		// this is normal at the start of the process
		// flag the is_self entry in nodes so it won't do try again
		this.connect_node.is_self = true;

		// disconnect
		// this will start a reconnect, and another node will be attempted
		this.client.end();

	} else if (j.type === 'pong') {
		// calculate the rtt between this node and the server it is connected to
		var rtt = Date.now() - j.ts;

		this.connect_node.rtt = rtt;
		//console.log(rtt + 'ms RTT to server');

		this.connect_node.rtt_array.push(rtt);
		if (this.connect_node.rtt_array.length > this.max_ping_count) {
			// keep the latest dt.max_ping_count by removing the first and oldest
			this.connect_node.rtt_array.shift();
		}

		// update the last_primary_connection date
		this.connect_node.last_primary_connection = Date.now();

		// update the server's node_id
		this.connect_node.node_id = j.node_id;

	} else if (j.type === 'distant_node') {
		// a client node sent a distant node

		if (j.ip === null) {
			// this is a server node sending itself to a client that sent a distant_node
			// replace the null ip with socket.remoteAddress
			j.ip = this.clean_remote_address(this.client.remoteAddress);
		}

		var exists = false;
		var l = 0;
		while (l < this.distant_nodes.length) {

			if (this.distant_nodes[l].node_id === j.node_id) {
				exists = true;
				this.distant_nodes[l].ts = Date.now();
				break;
			}

			l++;

		}

		if (exists === false) {
			// there is no existing path to this distant client

			// add to this.distant_nodes that are tested for improved connection quality
			// and may be added as nodes
			this.distant_nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, ts: Date.now(), test_status: 'pending', rtt: -1, rtt_array: [], test_failures: 0});

		}

	} else if (j.type === 'add_object') {

		// the server node sent an object

		// get the hash
		var sha256_hash = this.object_sha256_hash(j.object);

		// make sure it does not already exist
		var c = 0;
		while (c < this.objects.length) {
			var obj = this.objects[c];
			if (obj[0] === sha256_hash) {
				console.log('server sent duplicate object in add_object', j.object);
				return;
			}
			c++;
		}

		// this.objects is an array of [sha265_hash, object]
		var o = [sha256_hash, j.object];
		this.objects.push(o);

		console.log('server sent add_object to this node', o, this.objects.length);

		// send to all the connected clients
		var c = 0;
		while (c < this.nodes.length) {
			if (this.nodes[c].type === 'client') {
				if (this.nodes[c].conn) {
					this.server_send(this.nodes[c].conn, {type: 'add_object', object: j.object});
				}
			}
			c++;
		}

	} else if (j.type === 'object_diff') {

		// the server node sent it's list of object sha256 checksums/hashes
		console.log('server node sent object_diff', j, this.objects);

	}

}

dt.prototype.object_sha256_hash = function(j) {

	// an object must be sorted to be hashed

	// all sub objects should be sorted too

	// sort the object keys alphabetically
	const ordered = Object.keys(j).sort().reduce(
		(obj, key) => {
			obj[key] = j[key];
			return obj;
		},
	{}
	);

	// create a sha256 hash from the object
	var sha256_hash = crypto.createHash('sha256');
	sha256_hash.update(JSON.stringify(ordered));;

	return sha256_hash.digest('hex');

}

dt.prototype.add_object = function(j) {

	// add an object to all the nodes in the network

	// get the hash
	var sha256_hash = this.object_sha256_hash(j);

	// make sure it does not already exist
	var c = 0;
	while (c < this.objects.length) {
		var obj = this.objects[c];
		if (obj[0] === sha256_hash) {
			return {error: true, error_msg: 'object already exists'};
		}
		c++;
	}

	// this.objects is an array of [sha265_hash, object]
	var o = [sha256_hash, j];
	this.objects.push(o);

	// send the object to the server
	this.client_send({type: 'add_object', object: j});

	// send the object to all the clients
	var c = 0;
	while (c < this.nodes.length) {
		if (this.nodes[c].type === 'client') {
			if (this.nodes[c].conn) {
				this.server_send(this.nodes[c].conn, {type: 'add_object', object: j});
			}
		}
		c++;
	}

}

dt.prototype.remove_object = function(j) {

	// remove an object from all nodes in the network

}

class EEmitter extends events {}
dt.prototype.emitter = new EEmitter();

module.exports = dt;
