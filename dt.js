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
	this.message_ids = [];

	// advanced/non configurable options
	this.max_test_failures = 5;
	this.max_ping_count = 20;
	this.clean_interval = 5000;
	// if there is a better node to use as the primary, wait this long before disconnecting the existing primary client
	this.better_primary_switch_wait = 1000 * 60 * 20;
	// a node with a latency lower than this * the primary node latency avg will cause a primary client reconnect
	this.better_primary_latency_multiplier = .7;
	// wait this long before purging an unreachable node
	this.purge_node_unreachable_wait = 1000 * 60 * 60;
	// retest after a successful test at this interval
	this.retest_wait_period = 1000 * 60 * 10;
	// do not allow messages with a duplicate message_id more than this often
	this.message_duplicate_expire = 1000 * 60 * 5;

	var c = 0;
	while (c < config.nodes.length) {
		// build the nodes objects for the initial nodes
		// initial nodes are servers that this node can connect to
		var ip_port = config.nodes[c].split(':');

		if (ip_port.length !== 2) {
			console.error('node is missing IP and port', config.nodes[c]);
			process.exit(1);
		}

		this.nodes.push({ip: ip_port[0], port: Number(ip_port[1]), is_self: false, origin_type: 'initial', primary_connection_failures: 0, node_id: null, rtt: -1, rtt_array: [], connected_as_primary: false, test_status: 'pending', test_failures: 0, last_ping_time: null, conn: undefined});

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

		console.log('client connected', conn.remoteAddress);

		// add the client id
		// because the client end event may happen after a reconnect
		conn.client_id = crypto.randomUUID();

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
						return;
					}

					// type open is the first message
					if (vm.type === 'open') {

						// this is an authorized connection
						ipac.modify_auth(this.dt_object.ip_ac, true, conn.remoteAddress);

						// this is a directly connected node that is a client of this server

						// get the node ip address
						var node_ip = this.dt_object.clean_remote_address(conn.remoteAddress);

						// add the node_id to the conn object
						conn.node_id = vm.node_id;

						// add the node to the conn object
						conn.node = {ip: node_ip, port: vm.listening_port, is_self: false, origin_type: 'client', primary_connection_failures: 0, node_id: vm.node_id, client_id: conn.client_id, conn: conn, rtt: -1, rtt_array: [], connected_as_primary: false, test_status: 'pending', test_failures: 0, last_ping_time: Date.now()};

						console.log(vm.listening_port + ' opened a client connection\n\n');

						var updated = false;
						var c = 0;
						// tell all other clients that this node connected
						while (c < this.dt_object.nodes.length) {

							var n = this.dt_object.nodes[c];

							if (n.node_id === vm.node_id || (n.ip === node_ip && n.port === vm.listening_port)) {
								// update the node
								// this will not set with the reference n (n = conn.node fails to set without error)
								this.dt_object.nodes[c] = conn.node
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
							// add node to this.nodes
							this.dt_object.nodes.push(conn.node);
						}

						// send the known nodes as type: distant_node
						// to the client that connected
						var c = 0;
						while (c < this.dt_object.nodes.length) {

							var n = this.dt_object.nodes[c];
							if (n.connected_as_primary === true) {
								// the primary client is connected to a server
							} else {
								this.dt_object.server_send(conn, {type: 'distant_node', ip: n.ip, port: n.port, node_id: n.node_id});
							}

							c++;
						}

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

		});

		conn.on('end', function() {
			console.log('client disconnected');
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
		console.log('server bound', this.dt_object.port);

		// connect to a node
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
		console.log('\ndt.connect() total nodes', this.dt_object.nodes.length);

		// find the node with the lowest primary_connection_failures
		// this ensures that the primary connection is to a stable node
		var lowest_primary_connection_failures = -1;
		var primary_node = {};
		var lowest_avg_rtt = -1;

		var c = 0;
		while (c < this.dt_object.nodes.length) {

			var n = this.dt_object.nodes[c];

			var n_avg = this.dt_object.rtt_avg(n.rtt_array);

			console.log('test primary node against primary_connection_failures', n.node_id, n.ip, n.port, n.primary_connection_failures);

			if (n.is_self === true) {
				// do not attempt connection to self
				console.log('\tskipped as self');
				c++;
				continue;
			}

			if (this.dt_object.node_connected(n) === true) {
				// do not attempt connection to nodes that are already connected
				// a connection object means the node is connected
				console.log('\tskipped as connected client');
				c++;
				continue;
			}

			// finding the node with the lowest primary_connection_failures
			if (n.primary_connection_failures < lowest_primary_connection_failures || lowest_primary_connection_failures === -1) {
				primary_node = n;
				lowest_avg_rtt = n_avg;
				lowest_primary_connection_failures = n.primary_connection_failures;

				console.log('better primary node selection against primary_connection_failures');
			}

			c++;

		}

		// primary_node has the lowest primary_connection_failures
		// test the nodes that equal the primary_connection_failures count
		// and choose the one with the lowest avg rtt
		// this ensures that the primary connection is stable and has a low round trip time
		var r = 0;
		while (r < this.dt_object.nodes.length) {
			var n = this.dt_object.nodes[r];

			var n_avg = this.dt_object.rtt_avg(n.rtt_array);

			console.log('test primary node against average rtt', n.node_id, n.ip, n.port, n_avg);

			if (n.is_self === true) {
				// skip self nodes
			} else if (isNaN(n_avg)) {
				// skip nodes with no average rtt
				console.log('\tskipped with no average rtt');
			} else if (n.primary_connection_failures > lowest_primary_connection_failures) {
				// skip nodes that have more primary_connection failures
				console.log('\tskipped per more primary_connection_failures than lowest');
			} else if (n_avg < lowest_avg_rtt) {
				// there is a node with better latency
				primary_node = n;
				lowest_avg_rtt = n_avg;

				console.log('better primary node selection against average rtt', n.node_id);
			}
			r++;
		}

		if (Object.keys(primary_node).length === 0) {
			// this node has no nodes to connect to
			// it should stay on to allow nodes to connect to it
			console.log('no nodes ready for connection');

			// try again
			this.dt_object.connect();
			return;
		}

		console.log('\n\n\n\n\n\n\nbest node for primary client connection', primary_node.ip, primary_node.port, primary_node.node_id, 'primary_connection_failures: ' + primary_node.primary_connection_failures, 'average rtt: ' + this.dt_object.rtt_avg(primary_node.rtt_array));

		// ping the server
		var ping;

		if (this.dt_object.client !== undefined) {
			this.dt_object.client.destroy();
		}

		this.dt_object.client = net.connect({port: primary_node.port, host: primary_node.ip, keepAlive: true}, function() {
			// 'connect' listener.
			console.log('primary client connected to', primary_node.ip, primary_node.port, primary_node.node_id);

			// set the start time of this connection
			primary_node.primary_connection_start = Date.now();

			// send node_id
			this.dt_object.client_send({type: 'open', node_id: this.dt_object.node_id, listening_port: this.dt_object.port});

			// send object_hashes
			var o_hashes = [];
			var n = 0;
			while (n < this.dt_object.objects.length) {
				// add the sha256 checksum to the array
				o_hashes.push(this.dt_object.objects[n][0]);
				n++;
			}
			this.dt_object.client_send({type: 'object_hashes', object_hashes: o_hashes});

			// ping the server
			// and send the previous rtt
			ping = setInterval(function() {

				this.dt_object.client_send({type: 'ping', node_id: this.dt_object.node_id, ts: Date.now(), previous_rtt: primary_node.rtt});

			}.bind({dt_object: this.dt_object}), this.dt_object.ping_interval);

		}.bind({dt_object: this.dt_object}));

		// set client timeout of the socket
		this.dt_object.client.setTimeout(this.dt_object.timeout);

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

					// type open is the first message
					if (vm.type === 'open') {

						// this is an authorized connection
						ipac.modify_auth(this.dt_object.ip_ac, true, conn.remoteAddress);

					} else {

						// parse the message
						this.dt_object.valid_primary_client_message(primary_node, JSON.parse(decrypted));

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

		});

		this.dt_object.client.on('end', function() {

			// stop pinging
			clearInterval(ping);

			primary_node.connected_as_primary = false;

			console.log('primary client disconnected from server node', primary_node.ip, primary_node.port, primary_node.node_id);

			// reconnect to the network
			this.dt_object.connect();

		}.bind({dt_object: this.dt_object}));

		this.dt_object.client.on('timeout', function() {

			console.error('primary client timeout', primary_node.ip, primary_node.port, primary_node.node_id);

			primary_node.connected_as_primary = false;

			// a connection timeout is a failure
			primary_node.primary_connection_failures++;

			// reconnect to the network
			this.dt_object.connect();

		}.bind({dt_object: this.dt_object}));

		this.dt_object.client.on('error', function(err) {

			console.error('primary client socket error', primary_node.ip, primary_node.port, this.dt_object.connect.node_id, err.toString());

			primary_node.connected_as_primary = false;

			// a connection error is a failure
			primary_node.primary_connection_failures++;

			// reconnect to the network
			this.dt_object.connect();

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
					// flag this node with remove so it will be removed in the clean routine
					node.remove = true;
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
			this.dt_object.client_send({type: 'test_ping', node_id: this.dt_object.node_id, ts: Date.now(), previous_rtt: node.rtt}, client);

		}.bind({dt_object: this.dt_object}), this.dt_object.ping_interval);

	}.bind({dt_object: this}));

	// set client timeout of the socket
	client.setTimeout(this.timeout);

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

				if (j.type === 'is_self') {

					node.node_id = j.node_id;
					node.is_self = true;
					node.test_status = 'is_self'
					console.log('ending test client connection to self');
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

					recieved_pings++;
					if (recieved_pings >= this.dt_object.max_ping_count) {
						// test success at dt.max_ping_count pings
						client.end();
						node.test_status = 'success';
						node.test_failures = 0;
						node.last_test_success = Date.now();

						console.log('node test success, avg rtt', this.dt_object.rtt_avg(node.rtt_array));

						if (is_distant_node === true) {

							// remove any distant_node entries that have the same ip and port
							// as the node_id may have changed
							var c = this.dt_object.distant_nodes.length-1;
							while (c >= 0) {
								var n = this.dt_object.distant_nodes[c];
								if (n.node_id === node.node_id) {
									// this is the same node
									// move this node to nodes so it will be connected to

									// make sure it does not already exist in nodes by ip:port
									var exists = false;
									var l = 0;
									while (l < this.dt_object.nodes.length) {
										var nn = this.dt_object.nodes[l];
										if (nn.ip === n.ip && nn.port === n.port) {
											// this IP and port already exist in nodes
											exists = true;
											break;
										}
										l++;
									}

									if (exists === false) {
										// add this distant node to nodes
										this.dt_object.nodes.push(JSON.parse(JSON.stringify(n)));
									}

									// flag this distant node with remove so it will be removed in the clean routine
									n.remove = true;

								} else {
									if (n.ip === node.ip && n.port === node.port) {
										// this is another entry with the same ip and port but a different node_id
										// remove it because only one node can run on a single IP and port

										// flag this node with remove so it will be removed in the clean routine
										n.remove = true;
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

	});

	client.on('end', function() {

		// stop pinging
		clearInterval(ping);

		console.log('disconnected from node in node test', node.ip, node.port, node.node_id);

	});

	client.on('timeout', function() {

		console.error('timeout connecting to node in node test', node.ip, node.port, node.node_id);
		node.test_status = 'failed';
		node.test_failures++;

	});

	client.on('error', function(err) {

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

		console.log('\nnode id: ' + this.dt_object.node_id);
		console.log('server has ' + this.dt_object.server._connections + ' connections on port', this.dt_object.port);
		if (this.dt_object.client) {
			console.log('primary client is connected to', this.dt_object.client.remoteAddress, this.dt_object.client.remotePort);
		} else {
			console.log('primary client is not connected');
		}
		console.log('node objects', this.dt_object.objects.length);
		console.log('non expired message_ids', this.dt_object.message_ids.length);

		var v = this.dt_object.message_ids.length-1;
		while (v >= 0) {
			var m = this.dt_object.message_ids[v];

			if (Date.now() - m[1] > this.dt_object.message_duplicate_expire) {
				// message with this message_id can only arrive once within the time of dt.message_duplicate_expire
				this.dt_object.message_ids.splice(v, 1);
			}
			v--;
		}

		// test latency of distant nodes and nodes

		var c = this.dt_object.distant_nodes.length-1;
		while (c >= 0) {

			var n = this.dt_object.distant_nodes[c];

			if (n.remove === true) {
				// node flagged for removal
				this.dt_object.distant_nodes.splice(c, 1);
				c--;
				continue;
			}

			console.log('distant_node connected_as_primary: ' + n.connected_as_primary + ', origin_type: ' + n.origin_type + ', test_failures: ' + n.test_failures + ', test_status: ' + n.test_status + ', ' + n.ip + ':' + n.port + ', node_id: ' + n.node_id + ', primary_connection_failures: ' + n.primary_connection_failures + ', last_ping_time: ' + ((Date.now() - n.last_ping_time) / 1000) + 's ago, test_start: ' + ((Date.now() - n.test_start) / 1000) + 's ago, rtt_array(' + n.rtt_array.length + '): ' + this.dt_object.rtt_avg(n.rtt_array) + 'ms AVG RTT, rtt: ' + n.rtt + 'ms RTT');

			if (n.last_test_success !== undefined) {

				// remove any node that has not had a last_test_success in dt.purge_node_unreachable_wait
				if (Date.now() - n.last_test_success > this.dt_object.purge_node_unreachable_wait) {
					this.dt_object.distant_nodes.splice(c, 1);
					c--;
					continue;
				}

			}

			if (n.test_status === 'pending') {

				// start a latency test on this distant node
				this.dt_object.test_node(n, true);

			} else if (n.test_status === 'failed') {

				if (n.test_failures <= this.dt_object.max_test_failures) {
					// retest distant node
					this.dt_object.test_node(n, true);
				} else {
					// if the node has failed this many times, remove it
					this.dt_object.distant_nodes.splice(c, 1);
				}

			} else if (n.test_status === 'success') {

				// if dt.retest_wait_period has passed since the last test
				// set the status to pending
				if (Date.now() - n.last_test_success > this.dt_object.retest_wait_period) {
					n.test_status = 'pending';
				}

			}

			c--;
		}

		var primary_node = null;

		var l = this.dt_object.nodes.length-1;
		while (l >= 0) {

			var n = this.dt_object.nodes[l];

			if (n.remove === true) {
				// node flagged for removal
				this.dt_object.nodes.splice(l, 1);
				l--;
				continue;
			}

			console.log('node connected_as_primary: ' + n.connected_as_primary + ', origin_type: ' + n.origin_type + ', test_failures: ' + n.test_failures + ', test_status: ' + n.test_status + ', ' + n.ip + ':' + n.port + ', node_id: ' + n.node_id + ', primary_connection_failures: ' + n.primary_connection_failures + ', last_ping_time: ' + ((Date.now() - n.last_ping_time) / 1000) + 's ago, test_start: ' + ((Date.now() - n.test_start) / 1000) + 's ago, rtt_array(' + n.rtt_array.length + '): ' + this.dt_object.rtt_avg(n.rtt_array) + 'ms AVG RTT, rtt: ' + n.rtt + 'ms RTT');

			// initial nodes are not subject to unreachable
			// there address is written into the initial list before node launch
			// the node that is connected with the primary client is also not subject to unreachable
			if (n.last_test_success !== undefined && n.origin_type !== 'initial' && n.connected_as_primary !== true) {

				// remove any node that has not had a last_test_success in dt.purge_node_unreachable_wait
				if (Date.now() - n.last_test_success > this.dt_object.purge_node_unreachable_wait) {
					this.dt_object.nodes.splice(l, 1);
					l--;
					continue;
				}

			}

			if (n.connected_as_primary === false) {
				// this is not the node that is connected via the primary client

				if (n.test_status === 'pending') {

					// start a latency test on this node
					this.dt_object.test_node(n);

				} else if (n.test_status === 'failed') {

					if (n.test_failures <= 5) {
						// retest node
						this.dt_object.test_node(n);
					} else if (n.origin_type !== 'initial') {
						// if the node has failed this many times, remove it
						// initial nodes always stay
						this.dt_object.nodes.splice(l, 1);
					} else if (n.origin_type === 'initial') {
						// reset initial nodes test_status so they are available in the connection routine when reachable
						n.test_status = 'pending';
					}

				} else if (n.test_status === 'success') {

					// if dt.retest_wait_period has passed since the last test
					// set the status to pending
					if (Date.now() - n.last_test_success > this.dt_object.retest_wait_period) {
						n.test_status = 'pending';
					}

				}

			} else {
				// reference to use later
				primary_node = n;
			}

			l--;
		}

		// dt.connect() automatically reconnects if not connected
		if (primary_node !== null) {

			// primary node is connected

			// to ensure direct connectivity to the node with the lowest latency
			// examine node rtt times and disconnect to force a new connection to the node with the lowest latency if
			//	primary_connection_start of primary_node is > dt.better_primary_switch_wait
			//	a nodes avg rtt is .7 (dt.better_primary_latency_multiplier) or less of primary node

			if (Date.now() - primary_node.primary_connection_start > this.dt_object.better_primary_switch_wait) {

				var dc = false;
				var r = 0;
				while (r < this.dt_object.nodes.length) {
					var n = this.dt_object.nodes[r];

					var n_avg = this.dt_object.rtt_avg(n.rtt_array);
					var pn_avg = this.dt_object.rtt_avg(primary_node.rtt_array);

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
					console.log('ending primary client connection, there is a better connection available from another node');
					// the primary client should reconnect, there is a better connection/link to another node
					this.dt_object.client.end();
				}

			}

		}

	}.bind({dt_object: this}), this.clean_interval);

}

dt.prototype.server_send = function(conn, j) {

	if (conn === undefined) {
		console.log('server write impossible, conn object not available', j);
		return;
	}

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

dt.prototype.client_send = function(j, distant_node_client=null) {

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

	if (distant_node_client !== null) {
		// this is to a distant node
		//console.log('distant node client write', b.length, JSON.stringify(j));
		distant_node_client.write(b);
	} else if (this.client) {
		// send as the primary client
		//console.log('primary client write', b.length, JSON.stringify(j));
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

dt.prototype.node_connected = function(node) {

	// returns true or false
	if (node === undefined) {
		//console.log('node testing connected status undefined');
		return false;
	} else if (node.last_ping_time === null) {
		//console.log('node testing connected status last_ping_time=null');
		return false;
	} else if (Date.now() - node.last_ping_time > this.ping_interval * 2) {
		//console.log(node.ip + ':' + node.port + ' testing connected status', Date.now() - Number(node.last_ping_time));
		return false;
	} else {
		return true;
	}

}

dt.prototype.valid_server_message = function(conn, j) {

	// j is a valid message object
	// that was sent to this server
	//console.log('valid message to server', j);

	if (j.type === 'test_ping') {
		// respond with test_pong
		this.server_send(conn, {type: 'test_pong', node_id: this.node_id, ts: j.ts});
	} else if (j.type === 'ping') {

		// respond with pong
		this.server_send(conn, {type: 'pong', node_id: this.node_id, ts: j.ts});

		// set the last ping time
		conn.node.last_ping_time = Date.now();
		// set the rtt between this server and the client from j.previous_rtt
		// this is calculated by the client, and all nodes in the network are trusted by using the same key
		conn.node.rtt = j.previous_rtt;
		conn.node.rtt_array.push(j.previous_rtt);
		if (conn.node.rtt_array.length > this.max_ping_count) {
			// keep the latest dt.max_ping_count by removing the first
			conn.node.rtt_array.shift();
		}

	} else if (j.type === 'distant_node') {
		// the client node sent a distant node

		var exists = false;
		var l = 0;

		while (l < this.distant_nodes.length) {

			// distant nodes always have a node_id
			if (this.distant_nodes[l].node_id === j.node_id) {
				// node exists in distant nodes
				exists = true;
				this.distant_nodes[l].last_known_as_distant = Date.now();
				break;
			}

			l++;

		}

		l = 0;
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

			// add to this.distant_nodes that are tested for improved connection quality
			// and may be added as nodes
			this.distant_nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, last_known_as_distant: Date.now(), test_status: 'pending', rtt: -1, rtt_array: [], test_failures: 0, connected_as_primary: false, primary_connection_failures: 0, is_self: false, origin_type: 'distant', last_ping_time: null});

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
				} else if (n.node_id !== conn.node_id) {
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

		//console.log('client sent a message to this node', j);
		this.emitter.emit('message_recieved', j.message);

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
			} else if (n.node_id !== conn.node_id) {
				// not the one that sent it
				if (this.node_connected(n) === true) {
					this.server_send(n.conn, j, n);
				}
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
			if (this.nodes[c].node_id !== conn.node_id) {
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
		console.log('client node sent object_hashes', j.object_hashes.length);

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

dt.prototype.valid_primary_client_message = function(primary_node, j) {

	// j is a valid message object
	// that was sent to the primary client
	//console.log('valid primary client message', j);

	if (j.type === 'is_self') {
		// the client connected to itself
		// this is normal at the start of the process
		// flag the is_self entry in nodes so it won't do try again
		primary_node.is_self = true;

		// disconnect
		// this will start a reconnect, and another node will be attempted
		console.log('ending primary client connection to self');
		this.client.end();

	} else if (j.type === 'pong') {

		// update the last ping time
		primary_node.last_ping_time = Date.now();

		// flag this node as connected_as_primary
		primary_node.connected_as_primary = true;

		// prevent the primary node from being tested
		primary_node.last_test_success = Date.now();

		// calculate the rtt between this node and the server it is connected to
		var rtt = Date.now() - j.ts;

		primary_node.rtt = rtt;
		//console.log(rtt + 'ms RTT to server');

		primary_node.rtt_array.push(rtt);
		if (primary_node.rtt_array.length > this.max_ping_count) {
			// keep the latest dt.max_ping_count by removing the first and oldest
			primary_node.rtt_array.shift();
		}

		// update the server's node_id
		primary_node.node_id = j.node_id;

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

			// distant nodes always have a node_id
			if (this.distant_nodes[l].node_id === j.node_id) {
				exists = true;
				this.distant_nodes[l].last_known_as_distant = Date.now();
				break;
			}

			l++;

		}

		l = 0;
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
			// there is no existing path to this distant client

			// add to this.distant_nodes that are tested for improved connection quality
			// and may be added as nodes
			this.distant_nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, last_known_as_distant: Date.now(), test_status: 'pending', rtt: -1, rtt_array: [], test_failures: 0, connected_as_primary: false, primary_connection_failures: 0, is_self: false, origin_type: 'distant', last_ping_time: null});

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

		//console.log('server sent a message to this node', j);
		this.emitter.emit('message_recieved', j.message);

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
		console.log('server node sent object_hashes', j.object_hashes.length);

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

	}

}

dt.prototype.compare_object_hashes_to_objects = function(object_hashes) {
	// compares object_hashes to dt.objects
	// returns missing_in_hashes, missing_in_objects
	// requests each missing object from the dt network

	var missing_in_hashes = [];
	var missing_in_objects = [];

	// test each object in dt.objects for existance in object_hashes
	// problem is 0
	var c = 0;
	while (c < this.objects.length) {

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
			// add missing object
			missing_in_hashes.push(object);
		}

		c++;

	}

	if (c === 0) {
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
				// add missing hash
				missing_in_objects.push(hash);
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

	// send the object to all the clients
	var c = 0;
	while (c < this.nodes.length) {
		var n = this.nodes[c];
		if (n.connected_as_primary === true) {
			// the primary client is connected to a server
		} else if (this.node_connected(n) === true) {
			this.server_send(n.conn, {type: 'message', message: j, message_id: mid});
		}
		c++;
	}

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
		var n = this.nodes[c];
		if (n.connected_as_primary === true) {
			// the primary client is connected to a server
		} else if (this.node_connected(n) === true) {
			this.server_send(n.conn, {type: 'add_object', object: j});
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
