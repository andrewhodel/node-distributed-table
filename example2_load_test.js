var dt = require('./dt.js');
var process = require('process');
var crypto = require('crypto');
var fs = require('fs');

// connects to example1
var dt_node = new dt({port: 10001, key: 'asdf_any_length', nodes: ['127.0.0.1:9999']});

var log_file = './example2_load_test.log';
var log = '';

dt_node.emitter.addListener('started', function() {

	log += 'distributed table "started" event\n'

});

dt_node.emitter.addListener('object_added', function(object) {

	log += 'dt object_added event\n' + JSON.stringify(object) + '\n';

});

dt_node.emitter.addListener('object_removed', function(object) {

	log += 'dt object_removed event\n' + JSON.stringify(object) + '\n';

});

dt_node.emitter.addListener('message_received', function(m) {

	log += 'dt message_received event\n' + JSON.stringify(m) + '\n';

});

// send a message every 5 seconds
var last_number_of_objects = []
setInterval(function() {

	dt_node.send_message({some_key: 'an object is a nice message format if amongst online nodes'});

	// this node
	log += '\nnode id: ' + dt_node.node_id + '\n';
	log += 'server has ' + dt_node.server._connections + ' connections on port ' + dt_node.port + '\n';
	if (dt_node.client) {
		log += 'primary client is connected to ' + dt_node.client.remoteAddress + ':' + dt_node.client.remotePort + '\n';
	} else {
		log += 'primary client is not connected' + '\n';
	}
	log += 'node objects: ' + dt_node.objects.length + '\n';
	log += 'fragment_list: ' + dt_node.fragment_list.length + '\n';
	log += 'non expired message_ids: ' + dt_node.message_ids.length + '\n';
	log += 'active test count: ' + dt_node.active_test_count + '\n';

	// each node
	var l = dt_node.nodes.length-1;
	while (l >= 0) {

		var n = dt_node.nodes[l];

		log += '## connected: ' + dt_node.node_connected(n) + ', connected_as_primary: ' + n.connected_as_primary + ', origin_type: ' + n.origin_type + ', test_failures: ' + n.test_failures + ', test_status: ' + n.test_status + ', ' + n.ip + ':' + n.port + ', node_id: ' + n.node_id + ', primary_connection_failures: ' + n.primary_connection_failures + ', last_ping_time: ' + ((Date.now() - n.last_ping_time) / 1000) + 's ago, test_start: ' + ((Date.now() - n.test_start) / 1000) + 's ago, rtt_array(' + n.rtt_array.length + '): ' + dt_node.rtt_avg(n.rtt_array) + 'ms AVG RTT, rtt: ' + n.rtt + 'ms RTT, primary_client_connect_count: ' + n.primary_client_connect_count + ', test_count: ' + n.test_count + ', defrag_count: ' + n.defrag_count + ', last_data_time: ' + ((Date.now() - n.last_data_time) / 1000) + 's ago\n';

		l--;

	}

	// truncate log file
	var max_log_length = 1000 * 1000 * 10;
	if (log.length > max_log_length) {
		log = log.slice(log.length - max_log_length, log.length);
	}

	fs.writeFileSync(log_file, log);

	last_number_of_objects.push(dt_node.objects.length);

	if (last_number_of_objects.length >= 3) {
		if (last_number_of_objects[0] == last_number_of_objects[1] && last_number_of_objects[0] == last_number_of_objects[2] && last_number_of_objects[0] == last_number_of_objects[3]) {
			// the last 3 iterations had the same number of objects, there is a problem
			fs.appendFileSync(log_file, 'last 3 iterations had the same number of objects, process exited\n');
			process.exit(1);
		}
		last_number_of_objects = last_number_of_objects.splice(1, last_number_of_objects.length - 1);
	}

}, 5000);
