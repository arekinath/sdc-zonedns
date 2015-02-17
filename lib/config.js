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

var named = require('named');
var fs = require('fs');

var config = {};

var jsonFile = __dirname + "/../config.json";
var json = JSON.parse(fs.readFileSync(jsonFile, 'utf8'))

config.port = json.port ? json.port : 53;
config.bind = json.bind ? json.bind : "0.0.0.0";

config.ufds = json.ufds;
config.vmapi = json.vmapi;
config.cnapi = json.cnapi;
config.napi = json.napi;

config.ttl = json.ttl ? json.ttl : 300;

config.namesDbPath = json.nameStore ? json.nameStore : (__dirname + "/../names.db");

config.privateBase = json.base;
config.hostmaster = json.hostmaster;
config.hostname = json.me.hostname;
config.myRecs = json.me.records.map(function(r) {
	var cl = named[r.type + "Record"];
	return new cl(r.value);
});

if (json.reverseProxy && json.reverseProxy.enabled) {
	config.publicBase = json.reverseProxy.base;
	config.reverseProxy = json.reverseProxy.records.map(function(r) {
		var cl = named[r.type + "Record"];
		return new cl(r.value);
	});
}

config.ns = json.secondaryNs;
config.nsRecs = config.ns.map(function(h) { return new named.NSRecord(h); });

if (json.reverseProxy && json.reverseProxy.enabled) {
	config.privateZoneFile = __dirname + "/../private.zone";
	config.publicZoneFile = __dirname + "/../public.zone";
} else {
	config.privateZoneFile = __dirname + "/../base.zone";
}

module.exports = config;
