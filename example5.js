var dt = require('./dt.js');
var process = require('process');

// connects to example2
var dt_node = new dt({port: 10003, key: 'asdf_any_length', nodes: ['127.0.0.1:10002']});

dt_node.emitter.addListener('started', function() {
	console.log('distributed table "started" event');
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
