var dt = require('./dt.js');
var process = require('process');
var crypto = require('crypto');

// connects to example2
var dt_node = new dt({port: 10004, key: 'asdf_any_length', nodes: ['127.0.0.1:10000']});

dt_node.emitter.addListener('started', function() {
	console.log('distributed table "started" event');

	// wait until there is a connected node
	var connected_check_waiter = setInterval(function() {

		var send = false;
		var c = 0;
		while (c < dt_node.nodes.length) {
			var n = dt_node.nodes[c];

			console.log('node: ' + n.node_id + ', connected: ' + dt_node.node_connected(n));

			if (dt_node.node_connected(n) === true) {
				// there is at least one node to send to
				send = true;
			}

			c++;
		}

		if (send === true) {

			console.log('sending large file');

			// send large file
			dt_node.send_message({base_64_file_data: crypto.randomBytes(5000000).toString('base64')});

			// stop waiting for connected nodes
			clearInterval(connected_check_waiter);

		}

	}, 500);
});

dt_node.emitter.addListener('object_added', function(object) {

	console.log('dt object_added event', object)

});

dt_node.emitter.addListener('object_removed', function(object) {

	console.log('dt object_removed event', object)

});

dt_node.emitter.addListener('message_received', function(m) {

	console.log('dt message_received event', m);

});
