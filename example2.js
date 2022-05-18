var dt = require('./dt.js');
var process = require('process');

// connects to example1
var dt_node = new dt({port: 10000, key: 'asdf_any_length', nodes: ['127.0.0.1:9999']});

dt_node.emitter.addListener('started', function() {
	console.log('distributed table "started" event');
});
