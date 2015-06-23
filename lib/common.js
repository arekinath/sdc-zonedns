/*
sdc-zonedns
DNS server for resolving VM names automatically with SDC

Copyright (c) 2015, Alex Wilson and the University of Queensland
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation and/or
   other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

var Netmask = require('netmask').Netmask;
var Trie = require('trie-search');

var common = {};

common.vmFields = "uuid,state,destroyed,alias,owner_uuid,nics,server_uuid";

common.vmFilter = function vmFilter(vm) {
	return (!vm.destroyed) && (vm.state !== "failed");
}

var rfc1918Blocks = [
	new Netmask('10.0.0.0/8'),
	new Netmask('192.168.0.0/16'),
	new Netmask('172.16.0.0/12')
];
common.isRFC1918 = function(ip) {
	for (var i = 0; i < rfc1918Blocks.length; ++i) {
		if (rfc1918Blocks[i].contains(ip))
			return true;
	}
	return false;
};

common.recs = function(base) {
	var trie = new Trie('rkey', {splitOnRegEx: false});
	Object.defineProperty(this, '_trie', {value: trie, enumerable: false});
	Object.defineProperty(this, 'base', {value: base, enumerable: false});
}
common.recs.prototype = {};
common.recs.prototype.add = function(k, v) {
	if (!this[k]) {
		this[k] = [];
		this._trie.add({
			rkey: stringRev(k),
			key: k
		});
	}
	this[k].push(v);
};
common.recs.prototype.set = function(k, v) {
	if (!this[k]) {
		this._trie.add({
			rkey: stringRev(k),
			key: k
		});
	}
	this[k] = v;
}
common.recs.prototype.addIf = function(k, v) {
	if (this[k])
		this[k].push(v);
};
common.recs.prototype.lookup = function(k) {
	var kbase = k + "." + this.base;
	var candidates = this._trie.get(stringRev(k));
	for (var i = 0; i < candidates.length; ++i) {
		var c = candidates[i];
		var cbase = c.key + "." + this.base;
		if (dnsMatch(kbase, cbase))
			return this[c.key];
	}
	return false;
}
function stringRev(str) {
	return str.split('').reverse().join('');
}
function dnsMatch(zoneDomain, domain) {
	if (zoneDomain === domain)
		return true;
	if (zoneDomain === domain + ".")
		return true;
	var parts = domain.split(".");
	var ourparts = zoneDomain.split(".");
	var len = (parts.length > ourparts.length) ? parts.length : ourparts.length;
	for (var i = 0; i < len; ++i) {
		if (parts[i] !== "*" && parts[i] !== ourparts[i])
			return false;
	}
	return true;
}


common.deepCompare = function() {
	var i, l, leftChain, rightChain;

	function compare2Objects (x, y) {
		var p;
		if (isNaN(x) && isNaN(y) && typeof x === 'number' && typeof y === 'number') {
			return true;
		}
		if (x === y) {
			return true;
		}
		if ((typeof x === 'function' && typeof y === 'function') ||
				(x instanceof Date && y instanceof Date) ||
				(x instanceof RegExp && y instanceof RegExp) ||
				(x instanceof String && y instanceof String) ||
				(x instanceof Number && y instanceof Number)) {
			return x.toString() === y.toString();
		}
		if (!(x instanceof Object && y instanceof Object)) {
			return false;
		}
		if (x.isPrototypeOf(y) || y.isPrototypeOf(x)) {
			return false;
		}
		if (x.constructor !== y.constructor) {
			return false;
		}
		if (x.prototype !== y.prototype) {
			return false;
		}
		if (leftChain.indexOf(x) > -1 || rightChain.indexOf(y) > -1) {
			return false;
		}
		for (p in y) {
			if (y.hasOwnProperty(p) !== x.hasOwnProperty(p)) {
				return false;
			} else if (typeof y[p] !== typeof x[p]) {
				return false;
			}
		}
		for (p in x) {
			if (y.hasOwnProperty(p) !== x.hasOwnProperty(p)) {
				return false;
			} else if (typeof y[p] !== typeof x[p]) {
				return false;
			}

			switch (typeof (x[p])) {
				case 'object':
				case 'function':
					leftChain.push(x);
					rightChain.push(y);

					if (!compare2Objects (x[p], y[p])) {
						return false;
					}

					leftChain.pop();
					rightChain.pop();
					break;

				default:
					if (x[p] !== y[p]) {
						return false;
					}
					break;
			}
		}

		return true;
	}

	if (arguments.length < 1) {
		return true;
	}

	for (i = 1, l = arguments.length; i < l; i++) {
		leftChain = [];
		rightChain = [];

		if (!compare2Objects(arguments[0], arguments[i])) {
			return false;
		}
	}

	return true;
}

module.exports = common;
