var dt = require('./dt.js');
var process = require('process');
var crypto = require('crypto');

// connects to example2
var dt_node = new dt({port: 10004, key: 'asdf_any_length', nodes: ['127.0.0.1:10000']});

dt_node.emitter.addListener('started', function() {
	console.log('distributed table "started" event');

	// wait 5 seconds then send a large file (~5MB)
	setTimeout(function() {

		dt_node.send_message({base_64_file_data: crypto.randomBytes(5000000).toString('base64')});

	}, 5000);
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
