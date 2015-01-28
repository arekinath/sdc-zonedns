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

var common = {};

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

common.recs = function() { }
common.recs.prototype = {};
common.recs.prototype.add = function(k, v) {
	if (!this[k])
		this[k] = [];
	this[k].push(v);
};
common.recs.prototype.addIf = function(k, v) {
	if (this[k])
		this[k].push(v);
};

module.exports = common;
