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

	this.port = Number(config.port);
	this.key = Buffer.from(config.key);
	this.nodes = [];
	this.timeout = Number(config.timeout);
	this.ping_interval = Number(config.ping_interval);
	this.distant_nodes = [];

	var c = 0;
	while (c < config.nodes.length) {
		// build the nodes objects for the initial nodes
		// initial nodes are servers that this node can connect to
		var ip_port = config.nodes[c].split(':');

		if (ip_port.length !== 2) {
			console.error('node is missing IP and port', config.nodes[c]);
			process.exit(1);
		}

		this.nodes.push({ip: ip_port[0], port: Number(ip_port[1]), is_self: false, type: 'initial', failures: 0, node_id: null, rtt: -1, rtt_array: []})

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
			if (data_len === data.length) {

				// decrypt
				var decrypted = this.dt_object.decrypt(data);
				//console.log('decrypted', decrypted.length, decrypted.toString());

				// reset data and data_len
				data = Buffer.alloc(0);
				data_len = 0;

				try {

					// decrypted is a valid message
					this.dt_object.valid_server_message(conn, JSON.parse(decrypted));

					// if the decrypted message parses into JSON
					// this is an authorized connection
					ipac.modify_auth(this.dt_object.ip_ac, true, conn.remoteAddress);

				} catch (err) {
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
				data = Buffer.concat([data, chunk.slice(4)]);

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
		var lowest_failures = 0;
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

			if (n.failures <= lowest_failures || Object.keys(this.dt_object.connect_node).length === 0) {
				// finding the node with the lowest failures
				// connect to it
				this.dt_object.connect_node = n;
				lowest_failures = n.failures;
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

		console.log('node with lowest failures', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

		// ping the server
		var ping;

		this.dt_object.client = net.connect({port: this.dt_object.connect_node.port, host: this.dt_object.connect_node.ip, keepAlive: true}, () => {
			// 'connect' listener.
			console.log('primary client connected to', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

			// send node_id
			this.dt_object.client_send({type: 'open', node_id: this.dt_object.node_id, listening_port: this.dt_object.port});

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
			if (data_len === data.length) {

				// decrypt
				var decrypted = this.dt_object.decrypt(data);
				//console.log('decrypted', decrypted.length, decrypted.toString());

				// reset data and data_len
				data = Buffer.alloc(0);
				data_len = 0;

				try {
					// decrypted is a valid message
					this.dt_object.valid_client_message(JSON.parse(decrypted));
				} catch (err) {
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
				data = Buffer.concat([data, chunk.slice(4)]);

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
				this.dt_object.client.end();

			}

		});

		this.dt_object.client.on('end', () => {

			// stop pinging
			clearInterval(ping);

			console.log('node disconnected from server node', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

			// reconnect to the network
			this.dt_object.connect();

		});

		this.dt_object.client.on('timeout', () => {

			console.error('timeout connecting to node', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect_node.node_id);

			// a connection timeout is a failure
			this.dt_object.connect_node.failures++;

			// reconnect to the network
			this.dt_object.connect();

		});

		this.dt_object.client.on('error', (err) => {

			console.error('error connecting to node', this.dt_object.connect_node.ip, this.dt_object.connect_node.port, this.dt_object.connect.node_id, err.toString());

			// a connection error is a failure
			this.dt_object.connect_node.failures++;

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

dt.prototype.test_distant_node = function(distant_node) {

	// a distant_node could have been sent with no node_id from another node that has it as an initial node
	// and then again from a node that relayed it as a distant node.  It would be added twice
	// because the node_id was not found when adding

	// the origin node sending it with no node_id could do a distant test before sending it to gather the node id
	// but that would not ensure sending the initial node as a distant node if there was a network connection issue between
	// the origin node and that initial node

	// the solution is to not run a distant node test until all other nodes with the same ip and port have a test that is not pending

	// that will remove the node with a null node_id if a current test of that ip and port succeeds
	// and test it if any test of that ip and port fails

	/*
	var c = 0;
	while (c < this.distant_nodes.length) {
		var n = this.distant_nodes[c];

		if (distant_node.ip === n.ip && distant_node.port === n.port) {

			// same ip and port
			if (distant_node.node_id === n.node_id) {
				// this is the same node as distant_node
			} else if (distant_node.test_status !== 'current') {
				// this is another node with this ip and port that is currently being tested
				// this node will be tested again if the current test does not succeed and remove it by matching the ip and port
				return;
			}
		}

		c++;

	}
	*/

	//console.log('testing distant_node', distant_node);

	distant_node.test_start = Date.now();
	distant_node.test_status = 'current';
	distant_node.rtt = -1;
	distant_node.rtt_array = [];

	// distant node ping
	var ping;
	var recieved_pings = 0;

	var client = net.connect({port: distant_node.port, host: distant_node.ip, keepAlive: true}, function() {
		// 'connect' listener.
		console.log('connected to distant_node to test latency', distant_node.ip, distant_node.port);

		// send node_id
		//distant_node.client_send({type: 'open', node_id: distant_node.node_id, listening_port: distant_node.port});

		// ping the server
		// and send the previous rtt
		ping = setInterval(function() {

			// send with this node's node_id
			this.dt_object.client_send({type: 'distant_node_ping', node_id: this.dt_object.node_id, ts: Date.now(), previous_rtt: distant_node.rtt}, client);

		}.bind({dt_object: this.dt_object}), 2000);

	}.bind({dt_object: this}));

	// set client timeout of the socket
	client.setTimeout(this.timeout);

	var data = Buffer.alloc(0);
	var data_len = 0;

	var test_all_data = function() {

		//console.log('test_all_data()', data_len, data.length);
		if (data_len === data.length) {

			// decrypt
			var decrypted = this.dt_object.decrypt(data);
			//console.log('decrypted', decrypted.length, decrypted.toString());

			// reset data and data_len
			data = Buffer.alloc(0);
			data_len = 0;

			try {
				// decrypted is a valid message
				var j = JSON.parse(decrypted);

				if (j.type === 'distant_node_pong') {

					// set the node_id as it may have originated from a node storing it as initial that has yet to connect
					distant_node.node_id = j.node_id;

					// calculate the rtt between this node and the server it is connected to
					var rtt = Date.now() - j.ts;

					distant_node.rtt = rtt;
					//console.log(rtt + 'ms RTT to server');

					distant_node.rtt_array.push(rtt);

					recieved_pings++;
					if (recieved_pings >= 20) {
						// test success at 20 pings
						client.end();
						distant_node.test_status = 'success';

						console.log('distant_node test success, avg rtt', this.dt_object.rtt_avg(distant_node.rtt_array));

						/*
						// remove any distant_node entries that have the same ip and port
						// as the node_id may have changed
						var c = this.dt_object.distant_nodes.length-1;
						while (c >= 0) {
							var n = this.dt_object.distant_nodes[c];
							if (n.node_id === distant_node.node_id) {
								// this is the same entry
							} else {
								if (n.ip === distant_node.ip && n.port === distant_node.port) {
									// this is another entry with the same ip and port but a different node_id
									// remove it because only one node can run on a single IP and port
									this.dt_object.distant_nodes.splice(c, 1);
								}
							}
							c--;
						}
						*/

					}

				}

			} catch (err) {
				client.end();
				distant_node.test_status = 'failed';
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
			data = Buffer.concat([data, chunk.slice(4)]);

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
			client.end();
			distant_node.test_status = 'failed';

		}

	});

	client.on('end', () => {

		// stop pinging
		clearInterval(ping);

		console.log('disconnected from distant_node', distant_node.ip, distant_node.port, distant_node.node_id);

	});

	client.on('timeout', () => {

		console.error('timeout connecting to distant_node to test latency', distant_node.ip, distant_node.port, distant_node.node_id);
		distant_node.test_status = 'failed';

	});

	client.on('error', (err) => {

		console.error('error connecting to distant_node to test latency', distant_node.ip, distant_node.port, distant_node.node_id, err.toString());
		distant_node.test_status = 'failed';

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

		console.log('\nsorting hosts by latency');

		// test latency and expiration of nodes and distant nodes
		// remember that the node_id changes each time the node is restarted

		console.log('\tdistant nodes');
		var c = 0;
		while (c < this.dt_object.distant_nodes.length) {
			var n = this.dt_object.distant_nodes[c];
			console.log(n.test_status + ', ' + n.ip + ':' + n.port + ', ' + n.rtt + 'ms RTT, node_id: ' + n.node_id + ', ' + ((Date.now() - n.test_start) / 1000) + 's ago, ' + this.dt_object.rtt_avg(n.rtt_array) + 'ms AVG');

			if (n.test_status === 'pending') {

				// start a latency test on this pending host
				this.dt_object.test_distant_node(n);

			} else if (n.test_status === 'success') {

				// compare with other distant_nodes and nodes
				// to ensure direct connectivity to the node with the lowest latency

			}

			c++;
		}

		console.log('\tnodes');
		var l = 0;
		while (l < this.dt_object.nodes.length) {
			var n = this.dt_object.nodes[l];
			console.log(n.type + ', ' + n.ip + ':' + n.port + ', ' + n.rtt + 'ms RTT, ' + n.failures + ' failures, node_id: ' + n.node_id + ', ' + ((Date.now() - n.last_connected) / 1000) + 's ago, ' + this.dt_object.rtt_avg(n.rtt_array) + 'ms AVG');

			l++;
		}

		// send a long object to test
		/*
		var s = '';
		while (l < 50000) {
			s += 'a';
			l++;
		}
		this.dt_object.server_send(this.dt_object.conn, {type: 'test', node_id: this.dt_object.node_id, test: s});
		*/

	}.bind({dt_object: this}), 5000);

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

	// use client to send to a client that is not the main node client

	// expects a JSON object

	// encrypt the JSON object string
	var jsb = this.encrypt(Buffer.from(JSON.stringify(j)));

	//console.log('client_send() length', jsb.length);

	// write the length
	var b = Buffer.alloc(4);
	b.writeUInt32BE(jsb.length, 0);

	b = Buffer.concat([b, jsb]);

	if (client) {
		// this is to a distant node
		client.write(b);
	} else if (this.client) {
		// send to the main node client
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
	// that was sent to the server
	//console.log('valid server message', j);

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
				this.nodes[c].rtt = j.previous_rtt;
				this.nodes[c].last_connected = Date.now();

				this.nodes[c].rtt_array.push(j.previous_rtt);
				if (this.nodes[c].rtt_array.length > 20) {
					// keep the latest 20 by removing the first and oldest
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
				this.nodes[c] = {ip: this.clean_remote_address(conn.remoteAddress), port: j.listening_port, is_self: false, type: 'client', failures: 0, node_id: j.node_id, client_id: conn.client_id, conn: conn, last_connected: Date.now(), rtt: -1, rtt_array: []};
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
			this.nodes.push({ip: this.clean_remote_address(conn.remoteAddress), port: j.listening_port, is_self: false, type: 'client', failures: 0, node_id: j.node_id, client_id: conn.client_id, conn: conn, last_connected: Date.now(), rtt: -1, rtt_array: []})
		}

	} else if (j.type === 'distant_node') {
		// the server node sent a distant node

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
			this.distant_nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, ts: Date.now(), test_status: 'pending'});

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
		if (this.connect_node.rtt_array.length > 20) {
			// keep the latest 20 by removing the first and oldest
			this.connect_node.rtt_array.shift();
		}

		// update the last_connected date
		this.connect_node.last_connected = Date.now();

		// update the server's node_id
		this.connect_node.node_id = j.node_id;

	} else if (j.type === 'distant_node') {
		// a client node sent a distant node

		if (j.ip === null) {
			// this is a server node sending itself to a client that sent a distant_node
			// replace the null ip with socket.remoteAddress
			j.ip = this.clean_remote_address(this.client.socket.remoteAddress);
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
			this.distant_nodes.push({ip: j.ip, port: j.port, node_id: j.node_id, ts: Date.now(), test_status: 'pending'});

		}

	}

}

dt.prototype.add_object = function(j) {

	// add an object to all the nodes in the network

}

dt.prototype.remove_object = function(j) {

	// remove an object from all nodes in the network

}

class EEmitter extends events {}
dt.prototype.emitter = new EEmitter();

module.exports = dt;
