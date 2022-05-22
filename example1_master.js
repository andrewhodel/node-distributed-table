var dt = require('./dt.js');
var process = require('process');

// tries to connect to itself, no problem
// then tries to connect to example4
var dt_node = new dt({master: true, port: 9999, key: 'asdf_any_length', nodes: ['127.0.0.1:9999', '127.0.0.1:10002']});

dt_node.emitter.addListener('started', function() {
	console.log('distributed table "started" event');

	dt_node.add_object({test: 'test'});

});

dt_node.emitter.addListener('object_added', function(object) {

	console.log('dt object_added event', object)

});

dt_node.emitter.addListener('object_removed', function(object) {

	console.log('dt object_removed event', object)

});

dt_node.emitter.addListener('message_recieved', function(m) {

	console.log('dt message_recieved event', m);

});
