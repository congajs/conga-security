/**
 * Conga holds on to registered plugins from the
 * back-end application and provides the means to 
 * interact with the server
 * 
 * @param  {Object} config
 */
var Conga = function(config) {
	this.config = config;
	this.plugins = {};
	this.init();
};

Conga.prototype = {

	/**
	 * Initialize Conga.js!!!
	 * 
	 * @return {void}
	 */
	init: function() {
		
	},

	/**
	 * Register and initialize a plugin
	 * 
	 * @param  {String}   namespace
	 * @param  {Function} plugin 
	 * @return {void}
	 */
	plugin: function(namespace, plugin) {
		this.plugins[namespace] = new plugin(this.config);
	},

	/**
	 * Get a initialized plugin
	 * 
	 * @param  {String} namespace
	 * @return {Object}
	 */
	get: function(namespace) {
		return this.plugins[namespace];
	}

};

Conga.prototype.constructor = Conga;