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
	// master		boolean		one master node per dt
	// port			number		port to listen on
	// key			string		key to encrypt all traffic, common to all nodes
	// nodes		[string]	list of IPv4 and IPv6 addresses of some public nodes
	// timeout		number		timeout in milliseconds
	// ping_interval	number		ping interval in milliseconds

	var init_error = [];
	if (typeof(config.master) !== 'boolean') {
		config.master = false;
	} else if (typeof(config.port) !== 'number') {
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
	this.master = config.master;
	this.port = Number(config.port);
	this.key = Buffer.from(config.key);
	this.timeout = Number(config.timeout);
	this.ping_interval = Number(config.ping_interval);

	var m = Buffer.from('this is how each message is encrypted, be careful of javascript variable references and ignore those who harass with lies');
	// move this console.log() statement to line 80 to see why javascript references can be confusing while you are being harassed with lies and don't have pointers
	//console.log('\nencrypting', m);
	var enc = this.encrypt(m);
	//console.log('encrypted', enc);
	var dec = this.decrypt(enc);
	//console.log('decrypted', dec);

	// storage objects
	this.primary_node = null;
	this.nodes = [];
	this.objects = [];
	this.message_ids = [];
	this.fragment_list = [];

	// counters
	this.active_test_count = 0;

	// advanced/non configurable options
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
	// 1	show nodes and primary client connects
	// 2	show messages and what node they are from
	this.debug = 0;

	var c = 0;
	while (c < config.nodes.length) {
		// build the nodes objects for the initial nodes
		// initial nodes are servers that this node can connect to
		var ip_port = config.nodes[c].split(':');

		if (ip_port.length !== 2) {
			console.error('node is missing IP and port', config.nodes[c]);
			process.exit(1);
		}

		this.nodes.push({ip: ip_port[0], port: Number(ip_port[1]), is_self: false, origin_type: 'initial', primary_connection_failures: 0, node_id: null, rtt: -1, rtt_array: [], connected_as_primary: false, test_status: 'pending', test_failures: 0, last_ping_time: null, conn: undefined, test_count: 0, primary_client_connect_count: 0, defrag_count: 0, last_defrag: Date.now(), last_test_success: null, last_data_time: null});

		c++;

	}

	// to prevent the node from connecting to itself
	this.node_id = crypto.randomUUID();

	this.ip_ac = ipac.init();

	console.log('creating new dt node', this.port, this.node_id);

	this.server = net.createServer(function(conn) {
		// 'connection' listener.
		// this is a new client

		if (ipac.test_ip_allowed(this.dt_object.ip_ac, conn.remoteAddress) === false) {
			// this IP address has been blocked by node-ip-ac
			conn.end();
			return;
		}

		//console.log('client connected', conn.remoteAddress);

		// create the client id
		conn.client_id = crypto.randomUUID();

		conn.node_connecting = true;

		// make sure the open response has been received within the timeout
		setTimeout(function() {

			if (conn.node_connecting === true) {
				// disconnect if untrue
				conn.end();
			}

		}, this.dt_object.timeout);

		// set the recv_msn
		conn.recv_msn = 0;

		// send the client id
		this.dt_object.server_send(conn, {type: 'client_id', client_id: conn.client_id});

		var data = Buffer.alloc(0);
		var data_len = 0;

		var test_all_data = function() {

			//console.log('server read test_all_data()', data_len, data.length);
			if (data_len <= data.length) {

				// decrypt the data_len
				var decrypted = this.dt_object.decrypt(data.subarray(0, data_len));
				//console.log('server decrypted read', decrypted.length, decrypted.toString());

				try {

					// decrypted is a valid message
					var vm = JSON.parse(decrypted);

					if (vm.node_id === this.dt_object.node_id) {
						// tell the client that it connected to itself
						this.dt_object.server_send(conn, {type: 'is_self', node_id: this.dt_object.node_id});
						conn.end();
						return;
					}

					/*
					console.log('server received a message');
					console.log('conn.recv_msn', conn.recv_msn);
					console.log('vm.msn', vm.msn);
					console.log('conn.client_id', conn.client_id);
					console.log(vm);
					*/

					if (conn.recv_msn !== vm.msn) {
						// disconnect if client is sending out of sequence
						if (this.dt_object.debug >= 1) {
							console.log('socket disconnected per invalid message sequence number');
						}
						conn.end();
						return;
					} else if (vm.client_id !== conn.client_id && conn.recv_msn !== 0) {
						// disconnect a different client_id after first message that sets the sequence number and client id before allowing any modifications
						if (this.dt_object.debug >= 1) {
							console.log('socket disconnected per invalid client_id');
						}
						conn.end();
						return;
					}

					// increment the recv_msn of the connection
					conn.recv_msn++;

					// type open is the first message
					if (vm.type === 'open') {

						// node is no longer connecting
						conn.node_connecting = false;

						// this is an authorized connection
						ipac.modify_auth(this.dt_object.ip_ac, true, conn.remoteAddress);

						// this is a directly connected node that is a client of this server
						// send an open response so the node's primary client can set the node_id
						this.dt_object.server_send(conn, {type: 'open', node_id: this.dt_object.node_id});

						// get the node ip address
						var node_ip = this.dt_object.clean_remote_address(conn.remoteAddress);

						//console.log(vm.listening_port + ' opened a client connection\n\n');

						var updated = false;
						var c = 0;
						// tell all other clients that this node connected
						while (c < this.dt_object.nodes.length) {

							var n = this.dt_object.nodes[c];

							if (n.node_id === vm.node_id || (n.ip === node_ip && n.port === vm.listening_port)) {

								// this is the node that connected
								// update the conn object on the node
								this.dt_object.nodes[c].conn = conn
								// set the node object on conn
								conn.node = this.dt_object.nodes[c];
								// update the last_data_time
								conn.node.last_data_time = Date.now();
								// set the node_id
								conn.node.node_id = vm.node_id;

								updated = true;

							} else if (this.dt_object.node_connected(n) === true) {
								// tell client nodes that a node connected with a distant_node message
								this.dt_object.server_send(n.conn, {type: 'distant_node', ip: node_ip, port: vm.listening_port, node_id: vm.node_id});
							}
							c++;
						}

						// tell the server node that a node connected with a distant_node message
						//console.log('sending distant_node to the server');
						this.dt_object.client_send({type: 'distant_node', ip: node_ip, port: vm.listening_port, node_id: vm.node_id});

						if (updated === false) {
							// add new node to this.nodes
							var i = this.dt_object.nodes.push({ip: node_ip, port: vm.listening_port, is_self: false, origin_type: 'client', primary_connection_failures: 0, node_id: vm.node_id, conn: conn, rtt: -1, rtt_array: [], connected_as_primary: false, test_status: 'pending', test_failures: 0, last_ping_time: null, test_count: 0, primary_client_connect_count: 0, defrag_count: 0, last_defrag: Date.now(), last_test_success: null, last_data_time: Date.now()});
							conn.node = this.dt_object.nodes[i];
						}

						// send the known nodes as type: distant_node
						// to the client that connected
						var c = 0;
						while (c < this.dt_object.nodes.length) {

							var n = this.dt_object.nodes[c];
							if (n.connected_as_primary === true) {
								// the primary client is connected to a server
							} else if (n.node_id === vm.node_id || (n.ip === node_ip && n.port === vm.listening_port)) {
								// this is the node that connected
							} else {
								this.dt_object.server_send(conn, {type: 'distant_node', ip: n.ip, port: n.port, node_id: n.node_id});
							}

							c++;
						}

						// the server sends the object hashes to clients regardless of having recieved the object_hashes
						// because the object_hashes diff routine on the master node(s) will repeatedly create a
						// remove_object message with the object hash until it is completely removed from the network

						// send object_hashes
						var o_hashes = [];
						var n = 0;
						while (n < this.dt_object.objects.length) {
							// add the sha256 checksum to the array
							o_hashes.push(this.dt_object.objects[n][0]);
							n++;
						}
						this.dt_object.server_send(conn, {type: 'object_hashes', object_hashes: o_hashes});

					} else {

						// parse the message
						this.dt_object.valid_server_message(conn, vm);

					}

				} catch (err) {
					console.error('error in server with a client authorization', err);
					// if the decrypted message does not parse into JSON
					// this is an invalid connection
					// add an unauthorized attempt to node-ip-ac
					ipac.modify_auth(this.dt_object.ip_ac, undefined, conn.remoteAddress);
					conn.end();
					return;
				}

				// reset data
				data = data.subarray(data_len, data.length);
				//console.log('new data.length', data.length);

				if (data.length > 0) {
					// get length
					data_len = data.readUInt32BE(0);
					data = data.subarray(4);
					test_all_data();
				} else {
					// no new data
					// reset data_len
					data_len = 0;
				}

				return;

			}

			// there was not enough data
			return;

		}.bind({dt_object: this.dt_object});

		conn.on('data', function(chunk) {

			try {

				// update the last_data_time for the client node
				if (conn.node !== undefined) {
					conn.node.last_data_time = Date.now();
				}

				if (data_len === 0) {
					// first chunk

					// read length
					data_len = chunk.readUInt32BE(0);

					if (conn.recv_msn === 0) {
						// this is the first message from a connection
						// if more than 1000 bytes are sent
						// disconnect the socket and add an invalid authorization attempt to node-ip-ac
						if (data_len > 1000 || data.length > 1000 || chunk.length > 1000) {
							ipac.modify_auth(this.dt_object.ip_ac, undefined, conn.remoteAddress);
							conn.end();
							return;
						}
					}

					//console.log('first chunk, data length', data_len);

					// add to data without length
					data = Buffer.concat([data, chunk.subarray(4)]);

					test_all_data();

				} else {

					// continue to read through data_len
					data = Buffer.concat([data, chunk]);

					test_all_data();

				}

			} catch (err) {
				console.log('socket read error', err);
			}

		}.bind({dt_object: this.dt_object}));

		conn.on('close', function() {
			//console.log('client disconnected');
		});

		conn.on('error', function(err) {
			console.error('client error', err);
		});

	}.bind({dt_object: this}));

	this.server.on('error', function(err) {
		console.error(err);
		process.exit(1);
	});

	this.server.listen(this.port, function() {
		//console.log('dt server bound', this.dt_object.port);

		// connect to a node, first attempt after the server is successfully started
		this.dt_object.connect();

		// start clean routine
		this.dt_object.clean();

		this.dt_object.emitter.emit('started');

	}.bind({dt_object: this}));

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
		if (this.dt_object.debug >= 1) {
			console.log('primary client connect, total nodes', this.dt_object.nodes.length);
		}

		// find the node with the lowest primary_connection_failures
		// this ensures that the primary connection is to a stable node
		var lowest_primary_connection_failures = -1;
		this.dt_object.primary_node = null;
		var lowest_avg_rtt = -1;
		var forced_connect = false;

		var c = 0;
		while (c < this.dt_object.nodes.length) {

			var n = this.dt_object.nodes[c];

			if (n.force_connect === true) {
				// force connect to this node
				this.dt_object.primary_node = n;
				// only force the connection once
				n.force_connect = false;
				forced_connect = true;
				break;
			}

			var n_avg = this.dt_object.rtt_avg(n.rtt_array);

			//console.log('test primary node against primary_connection_failures', n.node_id, n.ip, n.port, n.primary_connection_failures);

			if (n.is_self === true) {
				// do not attempt connection to self
				//console.log('\tskipped as self');
				c++;
				continue;
			}

			if (this.dt_object.node_connected(n) === true) {
				// do not attempt connection to nodes that are already connected
				// a connection object means the node is connected
				//console.log('\tskipped as connected client');
				c++;
				continue;
			}

			// finding the node with the lowest primary_connection_failures
			if (n.primary_connection_failures < lowest_primary_connection_failures || lowest_primary_connection_failures === -1) {
				this.dt_object.primary_node = n;
				lowest_avg_rtt = n_avg;
				lowest_primary_connection_failures = n.primary_connection_failures;

				//console.log('better primary node selection against primary_connection_failures');
			}

			c++;

		}

		if (forced_connect === false) {

			// this.dt_object.primary_node has the lowest primary_connection_failures
			// test the nodes that equal the primary_connection_failures count
			// and choose the one with the lowest avg rtt
			// this ensures that the primary connection is stable and has a low round trip time
			var r = 0;
			while (r < this.dt_object.nodes.length) {
				var n = this.dt_object.nodes[r];

				var n_avg = this.dt_object.rtt_avg(n.rtt_array);

				//console.log('test primary node against average rtt', n.node_id, n.ip, n.port, n_avg);

				if (n.is_self === true) {
					// skip self nodes
				} else if (isNaN(n_avg)) {
					// skip nodes with no average rtt
					//console.log('\tskipped with no average rtt');
				} else if (n.primary_connection_failures > lowest_primary_connection_failures) {
					// skip nodes that have more primary_connection failures
					//console.log('\tskipped per more primary_connection_failures than lowest');
				} else if (n_avg < lowest_avg_rtt) {
					// there is a node with better latency
					this.dt_object.primary_node = n;
					lowest_avg_rtt = n_avg;

					//console.log('better primary node selection against average rtt', n.node_id);
				}
				r++;
			}

		}

		if (this.dt_object.primary_node === null) {
			// this node has no nodes to connect to
			// it should stay on to allow nodes to connect to it
			if (this.dt_object.debug >= 1) {
				console.log('primary client connect, no nodes ready for connection');
			}

			// try again
			this.dt_object.connect();
			return;
		}

		if (this.dt_object.debug >= 1) {
			console.log('primary client connect', this.dt_object.primary_node.ip, this.dt_object.primary_node.port, this.dt_object.primary_node.node_id, 'primary_connection_failures: ' + this.dt_object.primary_node.primary_connection_failures, 'average rtt: ' + this.dt_object.rtt_avg(this.dt_object.primary_node.rtt_array));
		}

		// ping the server
		var primary_client_ping;
		var primary_client_send_object_hashes;
		this.dt_object.primary_node.object_hashes_received = false;

		this.dt_object.primary_node.primary_client_connect_count++;

		// set data_since_last_pong
		this.dt_object.primary_node.data_since_last_pong = 0;
		this.dt_object.primary_node.messages_since_last_pong = 0;

		// set last_test_success to null so the node isn't disconnected for not being tested
		this.dt_object.primary_node.last_test_success = null;

		if (this.dt_object.client !== undefined) {
			this.dt_object.client.destroy();
		}

		this.dt_object.client = net.connect({port: this.dt_object.primary_node.port, host: this.dt_object.primary_node.ip, keepAlive: false}, function() {
			// 'connect' listener.
			//console.log('primary client connected to', this.dt_object.primary_node.ip, this.dt_object.primary_node.port, this.dt_object.primary_node.node_id);

			// set last_data_time
			this.dt_object.primary_node.last_data_time = Date.now();

			this.dt_object.client.node_connecting = true;

			// make sure the open response has been received within the timeout
			setTimeout(function() {

				if (this.dt_object.client !== undefined) {
					if (this.dt_object.client.node_connecting === true) {
						// increment primary_connection_failures
						this.dt_object.primary_node.primary_connection_failures += 3;
						// disconnect if untrue
						this.dt_object.client.end();
					}
				}

			}.bind({dt_object: this.dt_object}), this.dt_object.timeout);

			// send node_id
			this.dt_object.client_send({type: 'open', node_id: this.dt_object.node_id, listening_port: this.dt_object.port});

			// send once object_hashes is received
			// a non master node **shall remove any objects that are not in the diff from itself before forwarding objects**
			primary_client_send_object_hashes = setInterval(function() {

				// if multiple master nodes exist, they must be synchronized before
				// allowing the master nodes to send their objects

				// they cannot diff because they have no concept of origin time as they could be thousands of years
				// between message and response while using a different origin time zone and not originating from unix time (random message from unknown source with shared key)
				//
				// this is also why origin timestamps are not that useful when you have relative locations
				// no reason to keep the origin time of every ship (or the memory)
				// no reason to know the origin time of a ship between two planets each with their own origin time
				// if you have a historical record of their relative locations
				//
				// packetized data reception and decoding is slowed by particles
				// every on/off stream/laser can be overwritten preventing moving the binary stream from packet data to parallel laser beams
				// because the timing cannot be reputable
				//
				// time exists, but you won't know the origin time (universally applicable) until you have the bounds of the universe to measure upon and room to store the locations of each object
				// you can always use the node-distributed-table fragment routine to figure out part of it though
				// https://github.com/andrewhodel/node-distributed-table/issues/2
				//
				// or maybe everything in the universe will use seconds forever, it's still a problem of origin time at large distances
				// with many devices because of the maintainence nightmare that is upgrading atomic clocks

				// you could modify add_object() to save all the data and be able to diff between master nodes, but then you would turn life into data
				// by needing infinite hard drive space, until the bounds of the universe are defined

				if (this.dt_object.primary_node.object_hashes_received === true || this.dt_object.master === true) {
					clearInterval(primary_client_send_object_hashes);
				} else {
					// non master nodes shall wait until the object hashes are received
					//console.log('primary client waiting to send object_hashes to server until recieved');
					return;
				}

				// send object_hashes
				var o_hashes = [];
				var n = 0;
				while (n < this.dt_object.objects.length) {
					// add the sha256 checksum to the array
					o_hashes.push(this.dt_object.objects[n][0]);
					n++;
				}
				this.dt_object.client_send({type: 'object_hashes', object_hashes: o_hashes});

			}.bind({dt_object: this.dt_object}), 200);

			// ping the server
			// and send the previous rtt
			primary_client_ping = setInterval(function() {

				this.dt_object.client_send({type: 'ping', node_id: this.dt_object.node_id, ts: Date.now(), previous_rtt: this.dt_object.primary_node.rtt});

			}.bind({dt_object: this.dt_object}), this.dt_object.ping_interval);

		}.bind({dt_object: this.dt_object}));

		// set the start time of this connection
		this.dt_object.primary_node.primary_connection_start = Date.now();

		// set client timeout of the socket
		this.dt_object.client.setTimeout(this.dt_object.timeout);

		// set the recv_msn
		this.dt_object.client.recv_msn = 0;

		var data = Buffer.alloc(0);
		var data_len = 0;

		var test_all_data = function() {

			//console.log('primary client read test_all_data()', data_len, data.length);
			if (data_len <= data.length) {

				// decrypt the data_len
				var decrypted = this.dt_object.decrypt(data.subarray(0, data_len));
				//console.log('primary client decrypted read', decrypted.length, decrypted.toString());

				try {

					// decrypted is a valid message
					var vm = JSON.parse(decrypted);

					// update the client_id (socket id) sent from the server
					//console.log('primary client response with client_id', vm.client_id);
					this.dt_object.client.client_id = vm.client_id;

					if (this.dt_object.client.recv_msn !== vm.msn) {
						// increment primary_connection_failures
						this.dt_object.primary_node.primary_connection_failures += 3;
						// disconnect per out of sequence msn
						console.log('disconnecting from server per out of sequence msn');
						this.dt_object.client.end();
						return;
					}
					this.dt_object.client.recv_msn++;

					// type: 'open' is the response to the sent type: 'open' message
					// when there is a valid connection
					if (vm.type === 'open') {

						// set the node_id
						this.dt_object.primary_node.node_id = vm.node_id;

						// set connecting = false on the client
						this.dt_object.client.node_connecting = false;

						if (this.dt_object.primary_node.primary_connection_failures > 0) {
							// a successful open response to the primary client should decrement the primary_connection_failures
							// if it isn't already perfect
							this.dt_object.primary_node.primary_connection_failures--;
						}

						// send the connected nodes
						var cn = [];

						var c = 0;
						while (c < this.dt_object.nodes.length) {
							var n = this.dt_object.nodes[c];
							if (n.connected_as_primary === true) {
								// the primary client is connected to a server
							} else if (this.dt_object.node_connected(n) === true) {
								cn.push({ip: n.ip, port: n.port, node_id: n.node_id});
							}
							c++;
						}
						this.dt_object.client_send({type: 'connected_nodes', node_id: this.dt_object.node_id, connected_nodes: cn});

					} else {

						// parse the message
						this.dt_object.valid_primary_client_message(vm);

					}

				} catch (err) {
					console.error('error in primary client authorization to server', err);
					return;
				}

				// reset data
				data = data.subarray(data_len, data.length);
				//console.log('new data.length', data.length);

				if (data.length > 0) {
					// get length
					data_len = data.readUInt32BE(0);
					data = data.subarray(4);
					test_all_data();
				} else {
					// no new data
					// reset data_len
					data_len = 0;
				}

				return;

			}

			// there was not enough data
			return;

		}.bind({dt_object: this.dt_object});

		this.dt_object.client.on('data', function(chunk) {

			try {

				// update the last_data_time for the primary node
				this.dt_object.primary_node.last_data_time = Date.now();

				if (data_len === 0) {
					// first chunk

					// read length
					data_len = chunk.readUInt32BE(0);

					//console.log('first chunk, data length', data_len);

					// add to data without length
					data = Buffer.concat([data, chunk.subarray(4)]);

					test_all_data();

				} else {

					// continue to read through data_len
					data = Buffer.concat([data, chunk]);

					test_all_data();

				}

			} catch (err) {
				console.log('socket read error', err);
			}

		}.bind({dt_object: this.dt_object}));

		this.dt_object.client.on('close', function() {

			// stop pinging
			clearInterval(primary_client_ping);
			clearInterval(primary_client_send_object_hashes);

			this.dt_object.primary_node.connected_as_primary = false;

			if (this.dt_object.debug >= 1) {
				console.log('primary client disconnected from server node', this.dt_object.primary_node.ip, this.dt_object.primary_node.port, this.dt_object.primary_node.node_id);
			}

			this.dt_object.client = undefined;

			// reconnect to the network
			this.dt_object.connect();

		}.bind({dt_object: this.dt_object}));

		this.dt_object.client.on('timeout', function() {

			console.error('primary client timeout', this.dt_object.primary_node.ip, this.dt_object.primary_node.port, this.dt_object.primary_node.node_id);

			this.dt_object.primary_node.connected_as_primary = false;

			// a connection timeout is a failure
			this.dt_object.primary_node.primary_connection_failures += 3;

		}.bind({dt_object: this.dt_object}));

		this.dt_object.client.on('error', function(err) {

			console.error('primary client socket error', this.dt_object.primary_node.ip, this.dt_object.primary_node.port, this.dt_object.connect.node_id, err.toString());

			this.dt_object.primary_node.connected_as_primary = false;

			// a connection error is a failure
			this.dt_object.primary_node.primary_connection_failures += 3;

		}.bind({dt_object: this.dt_object}));

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

dt.prototype.test_node = function(node) {

	//console.log('testing node', node);

	node.test_start = Date.now();
	node.test_status = 'current';
	node.test_count++;

	// distant node ping
	var ping;
	var received_pings = 0;

	var client = net.connect({port: node.port, host: node.ip, keepAlive: false}, function() {
		// 'connect' listener.
		//console.log('test_node() connected', node.ip, node.port);

		// send the connected nodes
		var cn = [];

		var c = 0;
		while (c < this.dt_object.nodes.length) {
			var n = this.dt_object.nodes[c];
			if (n.connected_as_primary === true) {
				// the primary client is connected to a server
			} else if (this.dt_object.node_connected(n) === true) {
				cn.push({ip: n.ip, port: n.port, node_id: n.node_id});
			}
			c++;
		}

		this.dt_object.client_send({type: 'connected_nodes', node_id: this.dt_object.node_id, connected_nodes: cn}, client);

		// ping the server
		// and send the previous rtt
		ping = setInterval(function() {

			// send with this node's node_id
			this.dt_object.client_send({type: 'test_ping', node_id: this.dt_object.node_id, ts: Date.now(), previous_rtt: node.rtt}, client);

		}.bind({dt_object: this.dt_object}), this.dt_object.ping_interval);

	}.bind({dt_object: this}));

	// increment the active test count
	this.active_test_count++;

	// set client timeout of the socket
	client.setTimeout(this.timeout);

	// set the recv_msn
	client.recv_msn = 0;

	var data = Buffer.alloc(0);
	var data_len = 0;

	var test_all_data = function() {

		//console.log('test client read test_all_data()', data_len, data.length);
		if (data_len <= data.length) {

			// decrypt the data_len
			var decrypted = this.dt_object.decrypt(data.subarray(0, data_len));
			//console.log('test client decrypted read', decrypted.length, decrypted.toString());

			try {
				// decrypted is a valid message
				var j = JSON.parse(decrypted);

				// update the client_id (socket id) sent from the server
				//console.log('test client response with client id', j.client_id);
				client.client_id = j.client_id;

				if (client.recv_msn !== j.msn) {
					// disconnect per out of sequence msn
					console.log('disconnecting from server per out of sequence msn');
					node.test_status = 'failed'
					node.test_failures++;
					client.end();
					return;
				}
				client.recv_msn++;

				if (j.type === 'is_self') {

					// stop the node from being tested
					node.node_id = j.node_id;
					node.is_self = true;
					node.test_status = 'is_self'
					node.last_test_success = null;
					//console.log('ending test client connection to self');
					client.end();

				} if (j.type === 'test_pong') {

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

					received_pings++;
					if (received_pings >= this.dt_object.max_ping_count) {
						// test success at dt.max_ping_count pings
						client.end();
						node.test_status = 'success';
						node.test_failures = 0;
						node.last_test_success = Date.now();

						//console.log('test_node() success, avg rtt', this.dt_object.rtt_avg(node.rtt_array));

					}

				}

			} catch (err) {
				console.error('error with test_node()', err);
				client.end();
				node.test_status = 'failed';
				node.test_failures++;
			}

			// reset data
			data = data.subarray(data_len, data.length);
			//console.log('new data.length', data.length);

			if (data.length > 0) {
				// get length
				data_len = data.readUInt32BE(0);
				data = data.subarray(4);
				test_all_data();
			} else {
				// no new data
				// reset data_len
				data_len = 0;
			}

			return;

		}

		// there was not enough data
		return;

	}.bind({dt_object: this});

	client.on('data', function(chunk) {

		try {

			if (data_len === 0) {
				// first chunk

				// read length
				data_len = chunk.readUInt32BE(0);

				//console.log('first chunk, data length', data_len);

				// add to data without length
				data = Buffer.concat([data, chunk.subarray(4)]);

				test_all_data();

			} else {

				// continue to read through data_len
				data = Buffer.concat([data, chunk]);

				test_all_data();

			}

		} catch (err) {
			console.log('socket read error', err);
		}

	});

	client.on('close', function() {

		// stop pinging
		clearInterval(ping);
		this.dt_object.active_test_count--;

		//console.log('disconnected from node in test_node()', node.ip, node.port, node.node_id);

	}.bind({dt_object: this}));

	client.on('timeout', function() {

		console.error('timeout connecting to node in test_node()', node.ip, node.port, node.node_id);
		node.test_status = 'failed';
		node.test_failures++;

	}.bind({dt_object: this}));

	client.on('error', function(err) {

		console.error('error connecting to node in test_node()', node.ip, node.port, node.node_id, err.toString());
		node.test_status = 'failed';
		node.test_failures++;

	}.bind({dt_object: this}));

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

		if (this.dt_object.client) {
			// if the primary client is offline (has not sent data within the online threshold), disconnect it
			// this is because the remote side can open a socket then the network can block the traffic
			// and without the next test, there would be no determination of the node being offline
			if (this.dt_object.node_connected(this.dt_object.primary_node) === false) {
				this.dt_object.client.end();
			}
		}

		// show debug output
		if (this.dt_object.debug >= 1) {
			console.log('\nnode id: ' + this.dt_object.node_id);
			console.log('server has ' + this.dt_object.server._connections + ' connections on port', this.dt_object.port);
			if (this.dt_object.client) {
				console.log('primary client is connected to', this.dt_object.client.remoteAddress, this.dt_object.client.remotePort);
			} else {
				console.log('primary client is not connected');
			}
			console.log('node objects', this.dt_object.objects.length);
			console.log('fragment_list', this.dt_object.fragment_list.length);
			console.log('non expired message_ids', this.dt_object.message_ids.length);
			console.log('active test count', this.dt_object.active_test_count);
		}

		var v = this.dt_object.fragment_list.length-1;
		while (v >= 0) {
			var fn = this.dt_object.fragment_list[v];

			if (Date.now() - fn[1] > this.dt_object.purge_node_wait) {
				// expire fragment_list nodes with an update timestamp beyond now + purge_node_wait
				this.dt_object.fragment_list.splice(v, 1);
			}
			v--;
		}

		if (this.dt_object.active_test_count === 0) {

			// ensure that all non connected nodes exist in the fragment list
			var non_connected_node_not_in_fragment_list = null;

			// first test in nodes
			var c = 0;
			while (c < this.dt_object.nodes.length) {
				var n = this.dt_object.nodes[c];

				if (n.is_self === true) {
					// self does not need to be tested as a fragmented node
				} else if (this.dt_object.node_connected(n) === false) {
					// this is a non connected node, make sure it is in the fragment list
					// nodes in the fragment list are connected to a node that is distant
					// this ensures that a node or segment of nodes is not fragmented
					// by sending the non connected node a `defragment` message and starting that routine

					var found = false;
					var l = 0;
					while (l < this.dt_object.fragment_list.length) {

						var fn = this.dt_object.fragment_list[l];

						if (fn.ip === n.ip && fn.port === n.port) {
							found = true;
							break;
						}
						l++;
					}

					if (found === false) {
						non_connected_node_not_in_fragment_list = n;
						break;
					}

				}

				c++;
			}

			if (non_connected_node_not_in_fragment_list !== null && Date.now() - this.dt_object.last_defrag >= this.defrag_wait_period) {
				// the non connected node is not in the fragment_list
				// start the defragment routine
				this.dt_object.defragment_node(non_connected_node_not_in_fragment_list);
			}

		}

		var v = this.dt_object.message_ids.length-1;
		while (v >= 0) {
			var m = this.dt_object.message_ids[v];

			if (Date.now() - m[1] > this.dt_object.message_duplicate_expire) {
				// message with this message_id can only arrive once within the time of dt.message_duplicate_expire
				this.dt_object.message_ids.splice(v, 1);
			}
			v--;
		}

		// each node
		var l = this.dt_object.nodes.length-1;
		while (l >= 0) {

			var n = this.dt_object.nodes[l];

			if (n.remove === true) {
				// node flagged for removal
				this.dt_object.nodes.splice(l, 1);
				l--;
				continue;
			}

			if (n.conn !== undefined) {
				// there is a connection object
				if (n.conn.node_connecting === false) {
					// the node has finished connecting
					if (this.dt_object.node_connected(n) === false) {
						// the node is not connected, close the connection so it reconnects
						n.conn.end();
					}
				}
			}

			if (this.dt_object.debug >= 1) {
				console.log('## connected: ' + this.dt_object.node_connected(n) + ', connected_as_primary: ' + n.connected_as_primary + ', origin_type: ' + n.origin_type + ', test_failures: ' + n.test_failures + ', test_status: ' + n.test_status + ', ' + n.ip + ':' + n.port + ', node_id: ' + n.node_id + ', primary_connection_failures: ' + n.primary_connection_failures + ', last_ping_time: ' + ((Date.now() - n.last_ping_time) / 1000) + 's ago, test_start: ' + ((Date.now() - n.test_start) / 1000) + 's ago, rtt_array(' + n.rtt_array.length + '): ' + this.dt_object.rtt_avg(n.rtt_array) + 'ms AVG RTT, rtt: ' + n.rtt + 'ms RTT, primary_client_connect_count: ' + n.primary_client_connect_count + ', test_count: ' + n.test_count + ', defrag_count: ' + n.defrag_count + ', last_data_time: ' + ((Date.now() - n.last_data_time) / 1000) + 's ago');
			}

			// initial nodes are not subject to unreachable
			// their address is written into the initial list before node launch
			// the node that is connected with the primary client is also not subject to unreachable
			if (n.last_test_success !== null && n.origin_type !== 'initial' && n.connected_as_primary !== true && this.dt_object.node_connected(n) === false) {

				// remove any node that has not had a last_test_success in dt.purge_node_wait
				// is not initial
				// and is not connected
				if (Date.now() - n.last_test_success > this.dt_object.purge_node_wait) {
					this.dt_object.nodes.splice(l, 1);
					l--;
					continue;
				}

			} else if (n.test_failures > 10) {
				// remove node that has too many test_failures
				this.dt_object.nodes.splice(l, 1);
				l--;
				continue;
			}

			// the node has not been removed
			if (n.connected_as_primary === false) {
				// this is not the node that is connected via the primary client

				if (n.test_status === 'pending' && this.dt_object.node_connected(n) === false) {

					// start a latency test on this node that is not connected
					this.dt_object.test_node(n);

				} else if (n.test_status === 'current' && Date.now() - n.test_start > this.dt_object.retest_wait_period * 2) {

					// this node started a test but did not finish it within the retest wait period * 2
					// the socket can be opened then closed from the remote side without error or messages
					// start another latency test
					this.dt_object.test_node(n);

				} else if (n.test_status === 'failed') {

					if (n.origin_type === 'initial') {
						// reset initial nodes test_status so they are available in the connection routine when reachable
						n.test_status = 'pending';
					} else {
						// retest nodes that have not been removed
						this.dt_object.test_node(n);
					}

				} else if (n.test_status === 'success') {

					// if dt.retest_wait_period has passed since the last test
					// set the status to pending
					if (Date.now() - n.last_test_success > this.dt_object.retest_wait_period) {
						n.test_status = 'pending';
					}

				}

			}

			l--;
		}

		if (this.dt_object.primary_node !== null && this.dt_object.active_test_count === 0) {
			// the primary client is connected and there are no active tests

			// to ensure direct connectivity to the node with the lowest latency
			// examine node rtt times and disconnect to force a new connection to the node with the lowest latency if
			//	primary_connection_start of this.dt_object.primary_node is > dt.better_primary_wait
			//	a nodes avg rtt is .7 (dt.better_primary_latency_multiplier) or less of primary node

			if (Date.now() - this.dt_object.primary_node.primary_connection_start > this.dt_object.better_primary_wait) {

				var dc = false;
				var r = 0;
				while (r < this.dt_object.nodes.length) {
					var n = this.dt_object.nodes[r];

					var n_avg = this.dt_object.rtt_avg(n.rtt_array);
					var pn_avg = this.dt_object.rtt_avg(this.dt_object.primary_node.rtt_array);

					if (isNaN(n_avg) || isNaN(pn_avg)) {
						// skip nodes with no average rtt
					} else if (n_avg < pn_avg * this.dt_object.better_primary_latency_multiplier) {
						// there is a node with better latency
						// .7 < 1 * .7 = .7 false
						// .6 < 1 * .7 = .7 true
						dc = true;
						break;
					}
					r++;
				}

				if (dc === true) {
					//console.log('ending primary client connection, there is a better connection available from another node');
					// the primary client should reconnect, there is a better connection/link to another node
					this.dt_object.client.end();
				}

			}

		}

	}.bind({dt_object: this}), this.clean_interval);

}

dt.prototype.server_send = function(conn, j) {

	if (conn === undefined) {
		//console.log('server write impossible, conn object not available', j);
		return;
	}

	// add the random client id of the socket to the message
	j.client_id = conn.client_id;

	// each conn increments send_msn to know the order of the messages
	if (conn.send_msn === undefined) {
		conn.send_msn = 0;
	} else {
		conn.send_msn++;
	}

	// add the msn from the conn object that the server stores for the client
	j.msn = conn.send_msn;

	// add a random length string of random data
	// if a network is blocking by known length to create an unknown problem
	// it would be resolved by the fragment list being of random length
	// but this would be faster at the expense of a small number of bytes per message
	j.rl = crypto.randomBytes(Math.random() * 253).toString('hex');

	// expects a JSON object

	// encrypt the JSON object string
	var jsb = this.encrypt(Buffer.from(JSON.stringify(j)));

	//console.log('server_send() length', jsb.length);

	// write the length
	var b = Buffer.alloc(4);
	b.writeUInt32BE(jsb.length, 0);

	b = Buffer.concat([b, jsb]);

	if (conn.node) {
		//console.log('server_send()', conn.node.port, j);
	}

	//console.log('server write', b.length, JSON.stringify(j));
	conn.write(b);

}

dt.prototype.client_send = function(j, non_primary_client=null) {

	var selected_client;
	if (non_primary_client !== null) {
		// to be sent via the non primary client
		selected_client = non_primary_client;
	} else if (this.client) {
		// to be sent as the primary client
		selected_client = this.client;
	} else {
		console.error('client_send() to invalid client object');
		return;
	}

	// each client increments send_msn to know the order of the messages
	if (selected_client.send_msn === undefined) {
		selected_client.send_msn = 0;
	} else {
		selected_client.send_msn++;
	}

	//console.log('client_send() message', selected_client.send_msn, j.type);

	// send to a server
	// as the client

	// add the client id to the message (socket id)
	j.client_id = selected_client.client_id

	// add the message msn
	j.msn = selected_client.send_msn;

	// add a random length string of random data
	// if a network is blocking by known length to create an unknown problem
	// it would be resolved by the fragment list being of random length
	// but this would be faster at the expense of a small number of bytes per message
	j.rl = crypto.randomBytes(Math.random() * 253).toString('hex');

	// expects a JSON object

	// encrypt the JSON object string
	var jsb = this.encrypt(Buffer.from(JSON.stringify(j)));

	//console.log('client_send() length', jsb.length);

	// write the length
	var b = Buffer.alloc(4);
	b.writeUInt32BE(jsb.length, 0);

	b = Buffer.concat([b, jsb]);

	//console.log('client write', b.length, JSON.stringify(j));
	selected_client.write(b);

}

dt.prototype.decrypt_clonable = function(b) {

	console.log('decrypting', b);

	var unxor_b = this.unxor(this.key, b);

	console.log('decrypted', unxor_b);

	return unxor_b;

}

dt.prototype.encrypt_clonable = function(b) {

	console.log('encrypting', b);

	var xor_b = this.xor(this.key, b);

	console.log('encrypted', xor_b);

	return xor_b;

}

dt.prototype.decrypt = function(b) {

	/*
	XOR
	1 1 = 1
	0 1 = 0
	1 0 = 0
	*/

	//console.log('decrypting', b);

	// unxor the known random bytes length with this.key to get the random key
	var rk = this.unxor(this.key, b.subarray(0, 512));

	//console.log('random key', rk);

	// get the bytes after the random key length to get the value that is encrypted with the random key
	var r_b = b.subarray(rk.length);

	//console.log('value encrypted with random key', r_b);

	// unxor the value encrypted with the random key
	var ret = this.unxor(rk, r_b);

	//console.log('decrypted', ret);

	return ret;

}

dt.prototype.encrypt = function(b) {

	//console.log('encrypting', b);

	// create random key of a known length
	var rk = crypto.randomBytes(512);

	//console.log('random key', rk);

	// xor b with random key
	var r_b = this.xor(rk, b);

	//console.log('value encrypted with random key', r_b);

	// xor random key with this.key
	var r = this.xor(this.key, rk);

	// return xor random key with this.key + (xor b with random key)
	// decrypt uses this.key to get the random key, then uses the random key to get the original b
	var ret = Buffer.concat([r, r_b]);

	//console.log('encrypted', ret);

	return ret;

}

dt.prototype.unxor = function(key, b) {

	var c = 0;
	var key_position = 0;
	while (c < b.length) {

		if (key_position > key.length - 1) {
			key_position = 0;
		}

		b[c] = b[c] ^ key[key_position];
		c++;
		key_position++;

	}

	return b;

}

dt.prototype.xor = function(key, b) {

	var c = 0;
	var key_position = 0;
	while (c < b.length) {

		if (key_position > key.length - 1) {
			key_position = 0;
		}

		b[c] = key[key_position] ^ b[c];
		c++;
		key_position++;

	}

	return b;

}

dt.prototype.node_connected = function(node) {

	// returns true or false
	if (node === undefined) {
		//console.log('node testing connected status undefined');
		return false;
	} else if (node.last_data_time === null) {
		//console.log('node testing connected status last_data_time=null');
		return false;
	} else if (Date.now() - node.last_data_time > this.ping_interval * 2) {
		//console.log(node.ip + ':' + node.port + ' testing connected status', Date.now() - Number(node.last_data_time));
		return false;
	} else {
		return true;
	}

}

dt.prototype.valid_server_message = function(conn, j) {

	// j is a valid message object
	// that was sent to this server
	//console.log('valid message to server', j);

	if (j.type === 'defragment') {

		// compare j.fragment_list_length and the count of this node's fragment_list
		if (j.fragment_list_length >= this.fragment_list.length) {
			// this node has a smaller fragment list and should reconnect to the node that sent the defragment message
			// defragment_reconnect() to the node
			this.defragment_reconnect({ip: this.clean_remote_address(conn.remoteAddress), port: j.port, node_id: j.node_id});
		} else {
			// the sending node has a smaller fragment list and should reconnect
			this.server_send(conn, {type: 'defragment_greater_count'});
		}

		// only one valid_server message with or without response is in the defragment routine
		conn.end();

	} if (j.type === 'connected_nodes') {

		// update dt.fragment_list
		// each node in j.connected_nodes must be in dt.fragment_list with a current timestamp

		var c = 0;
		while (c < j.connected_nodes.length) {
			var cn = j.connected_nodes[c];

			if (cn.node_id === this.node_id) {
				// it is likely that another node will send this one as a connected node
				// the fragment_list should not contain this node (itself)
				c++;
				continue;
			}

			var cn_found = false;

			var l = 0;
			while (l < this.fragment_list.length) {
				var fn = this.fragment_list[l];
				if (fn.ip === cn.ip && fn.port === cn.port) {
					// update the timestamp
					this.fragment_list[l].ts = Date.now();
					cn_found = true;
					break;
				}
				l++;
			}

			if (cn_found === false) {
				// add to fragment_list
				cn.ts = Date.now();
				this.fragment_list.push(cn);
			}
			c++;
		}

	} else if (j.type === 'test_ping') {
		// respond with test_pong
		this.server_send(conn, {type: 'test_pong', node_id: this.node_id, ts: j.ts});
	} else if (j.type === 'ping') {

		// respond with pong
		this.server_send(conn, {type: 'pong', ts: j.ts});

		// set the last ping time
		// ping can arrive before the response to open is received
		// when the conn.node object is not yet defined
		if (conn.node !== undefined) {
			conn.node.last_ping_time = Date.now();

			// set the rtt between this server and the client from j.previous_rtt
			// this is calculated by the client, and all nodes in the network are trusted by using the same key
			conn.node.rtt = j.previous_rtt;
			conn.node.rtt_array.push(j.previous_rtt);
			if (conn.node.rtt_array.length > this.max_ping_count) {
				// keep the latest dt.max_ping_count by removing the first
				conn.node.rtt_array.shift();
			}

		}

	} else if (j.type === 'distant_node') {
		// the client node sent a distant node

		var exists = false;
		var l = 0;
		while (l < this.nodes.length) {

			// test nodes by ip and port
			if (this.nodes[l].ip === j.ip && this.nodes[l].port === j.port) {
				// node exists in nodes
				exists = true;
				break;
			}

			l++;

		}

		if (exists === false) {
			// there is no existing path to this distant node

			// add to this.nodes
			this.nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, last_known_as_distant: Date.now(), test_status: 'pending', rtt: -1, rtt_array: [], test_failures: 0, connected_as_primary: false, primary_connection_failures: 0, is_self: false, origin_type: 'distant', last_ping_time: null, test_count: 0, primary_client_connect_count: 0, defrag_count: 0, last_defrag: Date.now(), last_test_success: null, last_data_time: null});

			// the distant node may need to know of this node
			// send a distant_node message of this node to the client
			// with ip: null so that the client knows to use socket.remoteAddress
			// there is no requirement to do this more than once
			this.server_send(conn, {type: 'distant_node', ip: null, port: this.port, node_id: this.node_id});

			// send through to all connected clients
			var c = 0;
			while (c < this.nodes.length) {
				var n = this.nodes[c];
				if (n.connected_as_primary === true) {
					// the primary client is connected to a server
				} else if (n.node_id !== conn.node.node_id) {
					// not the one that sent it
					if (this.node_connected(n) === true) {
						//console.log('relaying distant_node to a client');
						this.server_send(n.conn, {type: 'distant_node', ip: j.ip, port: j.port, node_id: j.node_id});
					}
				}
				c++;
			}

		}

	} else if (j.type === 'message') {

		// the client node sent a message

		// make sure this message has not already arrived
		var n = 0;
		while (n < this.message_ids.length) {
			var mid = this.message_ids[n][0];
			if (mid === j.message_id) {
				// message already arrived
				return;
			}
			n++;
		}

		if (this.debug >= 2) {
			console.log(conn.node.node_id, conn.node.ip, conn.node.port, 'sent a message to this node as a client', j);
		}

		this.emitter.emit('message_received', j.message);

		// add the message_id
		this.message_ids.push([j.message_id, Date.now()]);

		// send the object to the server
		this.client_send(j);

		// send to all the connected clients except this one
		var c = 0;
		while (c < this.nodes.length) {
			var n = this.nodes[c];
			if (n.connected_as_primary === true) {
				// the primary client is connected to a server
			} else if (n.node_id !== conn.node.node_id) {
				// not the one that sent it
				if (this.node_connected(n) === true) {
					this.server_send(n.conn, j, n);
				}
			}
			c++;
		}

	} else if (j.type === 'remove_object') {

		// the client node wants an object removed

		// get the hash
		var sha256_hash = j.object_hash;

		// remove the local copy
		var c = 0;
		while (c < this.objects.length) {
			var obj = this.objects[c];
			if (obj[0] === sha256_hash) {
				this.emitter.emit('object_removed', obj[1]);
				this.objects.splice(c, 1);
				break;
			}
			c++;
		}

		//console.log('client sent remove_object to this node', sha256_hash);

		// send the hash to the server
		this.client_send({type: 'remove_object', object_hash: sha256_hash});

		// send the hash to all the clients
		var c = 0;
		while (c < this.nodes.length) {
			var n = this.nodes[c];
			if (n.connected_as_primary === true) {
				// the primary client is connected to a server
			} else if (this.node_connected(n) === true) {
				this.server_send(n.conn, {type: 'remove_object', object_hash: sha256_hash});
			}
			c++;
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
				//console.log('client sent duplicate object in add_object', j.object);
				return;
			}
			c++;
		}

		// this.objects is an array of [sha265_hash, object]
		var o = [sha256_hash, j.object];
		this.objects.push(o);

		//console.log('client sent add_object to this node', o, this.objects.length);
		this.emitter.emit('object_added', j.object);

		// send the object to the server
		this.client_send({type: 'add_object', object: j.object});

		// send to all the connected clients except this one
		var c = 0;
		while (c < this.nodes.length) {
			// except the one that sent it
			if (this.nodes[c].node_id !== conn.node.node_id) {
				if (this.node_connected(this.nodes[c]) === true) {
					this.server_send(this.nodes[c].conn, {type: 'add_object', object: j.object});
				}
			}
			c++;
		}

	} else if (j.type === 'request_object') {

		// send the object requested by hash to the requesting node
		var c = 0;
		while (c < this.objects.length) {
			if (this.objects[c][0] === j.object_hash) {
				this.server_send(conn, {type: 'add_object', object: this.objects[c][1]});
				break;
			}
			c++;
		}

	} else if (j.type === 'object_hashes') {

		// a client node sent it's list of object sha256 checksums/hashes
		//console.log('client node sent object_hashes', j.object_hashes.length);

		if (j.object_hashes.length === 0) {

			//console.log('sending all objects to client node', this.objects);

			// send all of them
			var c = 0;
			while (c < this.objects.length) {
				this.server_send(conn, {type: 'add_object', object: this.objects[c][1]});
				c++;
			}

			return;

		}

		var diff = this.compare_object_hashes_to_objects(j.object_hashes);
		var missing_in_hashes = diff[0];
		var missing_in_objects = diff[1];

		// send them to the client
		var c = 0;
		while (c < missing_in_hashes.length) {
			this.server_send(conn, {type: 'add_object', object: missing_in_hashes[c][1]});
			c++;
		}

		// this node is missing these objects
		var l = 0;
		while (l < missing_in_objects.length) {
			// request each object from the origin node
			this.server_send(conn, {type: 'request_object', object_hash: missing_in_objects[l]});
			l++;
		}

	}

}

dt.prototype.valid_primary_client_message = function(j) {

	// j is a valid message object
	// that was sent to the primary client
	//console.log('valid primary client message', j);

	if (j.type === 'is_self') {
		// the client connected to itself
		// this is normal at the start of the process
		// flag the is_self entry in nodes so it won't do try again
		this.primary_node.is_self = true;

		// disconnect
		// this will start a reconnect, and another node will be attempted
		//console.log('ending primary client connection to self');
		this.client.end();

	} else if (j.type === 'pong') {

		// update the last ping time
		this.primary_node.last_ping_time = Date.now();

		// flag this node as connected_as_primary
		this.primary_node.connected_as_primary = true;

		// calculate the rtt between this node and the server it is connected to
		var rtt = Date.now() - j.ts;

		// the primary client may have been receving a large data message
		// before this message
		// a ping message is ~400 bytes with random length data
		var normal_ping_size = 400;

		if (this.primary_node.data_since_last_pong > normal_ping_size * this.primary_node.messages_since_last_pong) {

			// the difference in size between a normal ping and the messages between this one and the last
			var ping_wait_size_diff = this.primary_node.data_since_last_pong - normal_ping_size;

			// rtt must be recalculated based on the size difference and normal_ping_size
			// this considers the data rate in the latency calculation while not requiring an extra socket or channel as ICMP uses
			//
			// set rtt = (rtt with the wait of the extra messages) divided by (diff / normal size)
			rtt = rtt / (ping_wait_size_diff / normal_ping_size);

			// then divide by the number of messages since last pong
			rtt = rtt / this.primary_node.messages_since_last_pong;

		}

		this.primary_node.messages_since_last_pong = 0;
		this.primary_node.data_since_last_pong = 0;

		this.primary_node.rtt = rtt;
		//console.log(rtt + 'ms RTT to server');

		this.primary_node.rtt_array.push(rtt);
		if (this.primary_node.rtt_array.length > this.max_ping_count) {
			// keep the latest dt.max_ping_count by removing the first and oldest
			this.primary_node.rtt_array.shift();
		}

	} else if (j.type === 'distant_node') {
		// a client node sent a distant node

		if (j.ip === null) {
			// this is a server node sending itself to a client that sent a distant_node
			// replace the null ip with socket.remoteAddress
			j.ip = this.clean_remote_address(this.client.remoteAddress);
		}

		var exists = false;
		var l = 0;
		while (l < this.nodes.length) {

			// test nodes by ip and port
			if (this.nodes[l].ip === j.ip && this.nodes[l].port === j.port) {
				// node exists in nodes
				exists = true;
				break;
			}

			l++;

		}

		if (exists === false) {
			// there is no existing path to this distant node

			// add to this.nodes
			this.nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, last_known_as_distant: Date.now(), test_status: 'pending', rtt: -1, rtt_array: [], test_failures: 0, connected_as_primary: false, primary_connection_failures: 0, is_self: false, origin_type: 'distant', last_ping_time: null, test_count: 0, primary_client_connect_count: 0, defrag_count: 0, last_defrag: Date.now(), last_test_success: null, last_data_time: null});

		}

	} else if (j.type === 'message') {

		// the server node sent a message

		// make sure this message has not already arrived
		var n = 0;
		while (n < this.message_ids.length) {
			var mid = this.message_ids[n][0];
			if (mid === j.message_id) {
				// message already arrived
				return;
			}
			n++;
		}

		if (this.debug >= 2) {
			console.log(this.primary_node.node_id, this.primary_node.ip, this.primary_node.port, 'sent a message to this node as a server', j);
		}

		this.emitter.emit('message_received', j.message);

		// add the message_id
		this.message_ids.push([j.message_id, Date.now()]);

		// send to all the connected clients
		var c = 0;
		while (c < this.nodes.length) {
			var n = this.nodes[c];
			if (n.connected_as_primary === true) {
				// the primary client is connected to a server
			} else if (this.node_connected(n) === true) {
				this.server_send(n.conn, j, n);
			}
			c++;
		}

	} else if (j.type === 'remove_object') {

		// the server node wants an object removed

		// get the hash
		var sha256_hash = j.object_hash;

		// remove the local copy
		var c = 0;
		while (c < this.objects.length) {
			var obj = this.objects[c];
			if (obj[0] === sha256_hash) {
				this.emitter.emit('object_removed', obj[1]);
				this.objects.splice(c, 1);
				break;
			}
			c++;
		}

		//console.log('client sent remove_object to this node', sha256_hash);

		// send the hash to all the clients
		var c = 0;
		while (c < this.nodes.length) {
			var n = this.nodes[c];
			if (n.connected_as_primary === true) {
				// the primary client is connected to a server
			} else if (this.node_connected(n) === true) {
				this.server_send(n.conn, {type: 'remove_object', object_hash: sha256_hash});
			}
			c++;
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
				//console.log('server sent duplicate object in add_object', j.object);
				return;
			}
			c++;
		}

		// this.objects is an array of [sha265_hash, object]
		var o = [sha256_hash, j.object];
		this.objects.push(o);

		//console.log('server sent add_object to this node', o, this.objects.length);
		this.emitter.emit('object_added', j.object);

		// send to all the connected clients
		var c = 0;
		while (c < this.nodes.length) {
			if (this.node_connected(this.nodes[c]) === true) {
				this.server_send(this.nodes[c].conn, {type: 'add_object', object: j.object});
			}
			c++;
		}

	} else if (j.type === 'request_object') {

		// send the object requested by hash to the requesting node
		var c = 0;
		while (c < this.objects.length) {
			if (this.objects[c][0] === j.object_hash) {
				this.client_send({type: 'add_object', object: this.objects[c][1]});
				break;
			}
			c++;
		}

	} else if (j.type === 'object_hashes') {

		// the server node sent it's list of object sha256 checksums/hashes
		//console.log('server node sent object_hashes', j.object_hashes.length);

		if (j.object_hashes.length === 0) {

			// send all of them
			var c = 0;
			while (c < this.objects.length) {
				this.client_send({type: 'add_object', object: this.objects[c][1]});
				c++;
			}

			return;

		}

		var diff = this.compare_object_hashes_to_objects(j.object_hashes);
		var missing_in_hashes = diff[0];
		var missing_in_objects = diff[1];

		// send them to the server
		var c = 0;
		while (c < missing_in_hashes.length) {
			this.client_send({type: 'add_object', object: missing_in_hashes[c][1]});
			c++;
		}

		// this node is missing these objects
		var l = 0;
		while (l < missing_in_objects.length) {
			// request each object from the origin node
			this.client_send({type: 'request_object', object_hash: missing_in_objects[l]});
			l++;
		}

		// flag object_hashes_received as true
		this.primary_node.object_hashes_received = true;

	}

	// set the size of this message
	this.primary_node.messages_since_last_pong += 1;
	this.primary_node.data_since_last_pong += JSON.stringify(j).length;
	//console.log('primary_node.data_since_last_pong', this.primary_node.data_since_last_pong);

}

dt.prototype.compare_object_hashes_to_objects = function(object_hashes) {
	// compares object_hashes to dt.objects
	// returns missing_in_hashes, missing_in_objects
	// requests each missing object from the dt network

	var missing_in_hashes = [];
	var missing_in_objects = [];

	// test each object in dt.objects for existance in object_hashes
	var c = this.objects.length-1;
	while (c >= 0) {

		var object = this.objects[c];
		var found = false;

		var l = 0;
		while (l < object_hashes.length) {
			var hash = object_hashes[l];
			if (hash === object[0]) {
				found = true;
				break;
			}
			l++;
		}

		if (found === false) {
			if (this.master === true) {
				// this node is a master node, it should send it's objects
				// add missing object
				missing_in_hashes.push(object);
			} else {
				// this node is a non master node, it should remove the objects that are not in the received object_hashes
				// non master nodes **shall remove any objects that are not in the diff from itself before forwarding objects**
				this.objects.splice(c, 1);
			}
		}

		c--;

	}

	if (this.objects.length === 0) {
		// all hashes are missing in dt.objects
		missing_in_objects = object_hashes;
	} else {

		// test each hash for existance in dt.objects
		var l = 0;
		while (l < object_hashes.length) {

			var hash = object_hashes[l];
			var found = false;

			var c = 0;
			while (c < this.objects.length) {
				var obj = this.objects[c];
				if (obj[0] === hash) {
					found = true;
					break;
				}
				c++;
			}

			if (found === false) {
				if (this.master === true) {
					// this node is a master node, it should send remove_object(hash) to the dt
					this.remove_object(hash);
				} else {
					// this node is a non master node, it should add the missing object
					// add missing hash
					missing_in_objects.push(hash);
				}
			}

			l++;

		}

	}

	return [missing_in_hashes, missing_in_objects];

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

dt.prototype.send_message = function(j) {

	// send a message to all the nodes in the network
	var mid = crypto.randomUUID();

	// add the message_id
	this.message_ids.push([mid, Date.now()]);

	// send the object to the server
	this.client_send({type: 'message', message: j, message_id: mid});

	if (this.debug >= 2 && this.primary_node !== null) {
		console.log('this node sent a message to server', this.primary_node.node_id, this.primary_node.ip, this.primary_node.port, mid, j);
	}

	// send the object to all the clients
	var c = 0;
	while (c < this.nodes.length) {
		var n = this.nodes[c];
		if (n.connected_as_primary === true) {
			// the primary client is connected to a server
		} else if (this.node_connected(n) === true) {
			this.server_send(n.conn, {type: 'message', message: j, message_id: mid});

			if (this.debug >= 2) {
				console.log('this node sent a message to client', n.node_id, n.ip, n.port, mid);
			}

		}
		c++;
	}

}

dt.prototype.add_object = function(j) {

	if (this.master !== true) {
		this.emitter.emit('error', 'dt.add_object', 'dt.add_object() requires this node to be a master node', j);
		return;
	}

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
		var n = this.nodes[c];
		if (n.connected_as_primary === true) {
			// the primary client is connected to a server
		} else if (this.node_connected(n) === true) {
			this.server_send(n.conn, {type: 'add_object', object: j});
		}
		c++;
	}

}

dt.prototype.remove_object = function(h) {

	if (this.master !== true) {
		this.emitter.emit('error', 'dt.remove_object', 'dt.remove_object() requires this node to be a master node', h);
		return;
	}

	// remove an object from all nodes in the network

	var hash_string = '';
	if (typeof(h) === 'string') {
		// remove by hash string
		hash_string = h;
	} else {

		// get the hash
		var sha256_hash = this.object_sha256_hash(h);

		// remove the local copy
		var c = 0;
		while (c < this.objects.length) {
			var obj = this.objects[c];
			if (obj[0] === sha256_hash) {
				this.objects.splice(c, 1);
				break;
			}
			c++;
		}

		hash_string = sha256_hash;

	}

	// send the hash to the server
	this.client_send({type: 'remove_object', object_hash: hash_string});

	// send the hash to all the clients
	var c = 0;
	while (c < this.nodes.length) {
		var n = this.nodes[c];
		if (n.connected_as_primary === true) {
			// the primary client is connected to a server
		} else if (this.node_connected(n) === true) {
			this.server_send(n.conn, {type: 'remove_object', object_hash: hash_string});
		}
		c++;
	}

}

dt.prototype.defragment_reconnect = function(node) {

	//console.log('defragmentation requires a primary client reconnect to a non connected node');

	// send a distant_node message via the existing primary client
	// if it exists
	if (this.primary_node !== undefined) {
		this.client_send({type: 'distant_node', ip: node.ip, port: node.port, node_id: node.node_id});
	}

	//console.log('reconnecting primary client to', node.ip, node.port);

	// set node.force_connect to true
	node.force_connect = true;

	if (this.client !== undefined) {
		// disconnect the primary client
		this.client.end();
	}

}

dt.prototype.defragment_node = function(node) {

	//console.log('defragment_node()', node.ip, node.port);

	node.defrag_count++;
	node.last_defrag = Date.now();

	var client = net.connect({port: node.port, host: node.ip, keepAlive: false}, function() {
		// 'connect' listener.
		//console.log('defragment_node() connected', node.ip, node.port);

		// send the defragment message with dt.port and fragment_list_length
		this.dt_object.client_send({type: 'defragment', fragment_list_length: this.dt_object.fragment_list.length, port: this.dt_object.port, node_id: this.dt_object.node_id}, client);

	}.bind({dt_object: this}));

	// set client timeout of the socket
	client.setTimeout(this.timeout);

	// set the recv_msn
	client.recv_msn = 0;

	var data = Buffer.alloc(0);
	var data_len = 0;

	var test_all_data = function() {

		//console.log('defragment client read test_all_data()', data_len, data.length);
		if (data_len <= data.length) {

			// decrypt the data_len
			var decrypted = this.dt_object.decrypt(data.subarray(0, data_len));
			//console.log('defragment client decrypted read', decrypted.length, decrypted.toString());

			try {
				// decrypted is a valid message
				var j = JSON.parse(decrypted);

				// update the client_id (socket id) sent from the server
				//console.log('defragment client response with client id', j.client_id);
				client.client_id = j.client_id;

				if (client.recv_msn !== j.msn) {
					// disconnect per out of sequence msn
					console.log('disconnecting from server per out of sequence msn');
					client.end();
					return;
				}
				client.recv_msn++;

				if (j.type === 'defragment_greater_count') {

					// defragment_reconnect() to the node
					this.dt_object.defragment_reconnect(node);

					client.end();

				}

			} catch (err) {
				console.error('error with defragment_node()', err);
			}

			// reset data
			data = data.subarray(data_len, data.length);
			//console.log('new data.length', data.length);

			if (data.length > 0) {
				// get length
				data_len = data.readUInt32BE(0);
				data = data.subarray(4);
				test_all_data();
			} else {
				// no new data
				// reset data_len
				data_len = 0;
			}

			return;

		}

		// there was not enough data
		return;

	}.bind({dt_object: this});

	client.on('data', function(chunk) {

		try {

			if (data_len === 0) {
				// first chunk

				// read length
				data_len = chunk.readUInt32BE(0);

				//console.log('first chunk, data length', data_len);

				// add to data without length
				data = Buffer.concat([data, chunk.subarray(4)]);

				test_all_data();

			} else {

				// continue to read through data_len
				data = Buffer.concat([data, chunk]);

				test_all_data();

			}

		} catch (err) {
			console.log('socket read error', err);
		}

	});

	client.on('close', function() {

		//console.log('disconnected from node in defragment_node()', node.ip, node.port, node.node_id);

	}.bind({dt_object: this}));

	client.on('timeout', function() {

		console.error('timeout connecting to node in defragment_node()', node.ip, node.port, node.node_id);

	}.bind({dt_object: this}));

	client.on('error', function(err) {

		console.error('error connecting to node in defragment_node()', node.ip, node.port, node.node_id, err.toString());

	}.bind({dt_object: this}));

}

class EEmitter extends events {}
dt.prototype.emitter = new EEmitter();

module.exports = dt;
