var dt = require('./dt.js');
var process = require('process');

// tries to connect to itself, no problem
// then tries to connect to example4
var dt_node = new dt({port: 9999, key: 'asdf_any_length', nodes: ['127.0.0.1:9999', '127.0.0.1:10002']});

dt_node.emitter.addListener('started', function() {
	console.log('distributed table "started" event');
});
