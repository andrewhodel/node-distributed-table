var dt = require('./dt.js');
var process = require('process');

var port = 9999;
if (process.argv[2]) {
	port = Number(process.argv[2]);
}

var dt_node = new dt({port: port, key: 'asdf_any_length', nodes: ['127.0.0.1:9999']});

dt_node.emitter.addListener('started', function() {
	console.log('distributed table "started" event');
});
