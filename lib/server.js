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
var sdc = require('sdc-clients');
var bunyan = require('bunyan');
var zonefile = require('dns-zonefile');
var fs = require('fs');
var net = require('net');
var async = require('async');

var log = bunyan.createLogger({name: 'zone-dns'});

var config = require('./config');
var resolver = require('./resolver');
var slaver = require('./slaver');

String.prototype.endsWith = function(suffix) {
	return this.indexOf(suffix, this.length - suffix.length) !== -1;
};

String.prototype.startsWith = function (str){
	return this.indexOf(str) == 0;
};

function Server() {
	this.ufdsConnected = false;

	this.privateZone = zonefile.parse(fs.readFileSync(config.privateZoneFile, 'utf8'));
	this.publicZone = zonefile.parse(fs.readFileSync(config.publicZoneFile, 'utf8'));

	var ns = named.createServer();
	this.ns = ns;

	ns.listen(config.port, config.bind, function() {
		log.info("DNS server started");
	});

	ns.listenTcp(config.port, config.bind);
	ns.on("query", this.handleQuery.bind(this));

	ns.sendRecs = sendRecs.bind(ns);

	config.ufds.log = log;
	var ufds = new sdc.UFDS(config.ufds);
	this.ufds = ufds;
	ufds.once('connect', function() {
		log.info("ufds: connected");
		this.ufdsConnected = true;
	}.bind(this));

	this.vmapi = new sdc.VMAPI(config.vmapi);
	this.cnapi = new sdc.CNAPI(config.cnapi);
	this.napi = new sdc.NAPI(config.napi);

	this.makeVMRecords = resolver.makeVMRecords;
	this.makeFileRecords = resolver.makeFileRecords;
	this.makeAXFRRecords = slaver.makeRecords;
}

Server.prototype.handleQuery = function(query) {
	var domain = query.name();
	var type = query.type();

	query.isPrivate = domain.endsWith(config.privateBase);
	query.isPublic = domain.endsWith(config.publicBase);

	if (type !== 'AXFR' && type !== 'NS') {
		config.nsRecs.forEach(function(r) {
			query.addAuthority(
				query.isPublic ? config.publicBase : config.privateBase,
				r, 3600);
		});
	}

	switch (type) {
		case 'AXFR':
			return this.handleAXFR(query);

		case 'NS':
			return this.handleNS(query);

		case 'A':
		case 'TXT':
			return this.handleResolve(query);

		case 'SOA':
			return this.handleSOA(query);

		default:
			log.info("got unsupported req type %j from %s", type, query._client.address);
			break;
	}
}

function makeSOA(domain) {
	var now = new Date();
	var serial = now.getYear();
	serial = serial * 12 + now.getMonth();
	serial = serial * 31 + now.getDay();
	serial = serial * 24 + now.getHours();
	serial = serial * 60 + now.getMinutes();
	serial = serial + 0x80000000;
	return new named.SOARecord(config.hostname + "." + domain, {
		serial: serial,
		admin: config.hostmaster,
		refresh: 60,
		retry: 60,
		expire: 181440,
		ttl: 300
	});
}

function sendRecs(query, recs, base) {
	if (base === undefined)
		base = (query.isPublic ? config.publicBase : config.privateBase);

	Object.keys(recs).forEach(function(k) {
		recs[k].forEach(function(rec) {
			var domain = k + "." + base;
			if (k.endsWith("."))
				domain = k.slice(0, -1);
			query.addAnswer(domain, rec, config.ttl);
		});
	});

	this.send(query);
}

Server.prototype.handleAXFR = function(query) {
	if (!query.isPrivate && !query.isPublic)
		return;

	var domain = query.name();

	log.info("making axfr for %s", query._client.address);

	var soa = makeSOA(domain);
	query.addAnswer(domain, soa, 60);
	this.ns.send(query);

	config.nsRecs.forEach(function(r) {
		query.addAnswer(domain, r, 3600);
	});
	if (query.isPublic) {
		config.reverseProxy.forEach(function(r) {
			query.addAnswer(domain, r, 3600);
		});
	}
	this.ns.send(query);

	var ns = this.ns;

	this.makeAXFRRecords(query, function(err, recs) {
		if (err) {
			query.addAnswer(domain, soa, 60);
			ns.send(query);
			return;
		}

		var i = 0;
		Object.keys(recs).forEach(function(k) {
			if (recs[k] && recs[k].length > 0) {
				recs[k].forEach(function(rec) {
					query.addAnswer(k + "." + domain, rec, config.ttl);
					i++;
					if (i > 199) {
						ns.send(query);
						i = 0;
					}
				});
			}
		});
		if (i > 0)
			ns.send(query);
		query.addAnswer(domain, soa, 60);
		ns.send(query);
	});
}

Server.prototype.handleNS = function(query) {
	if (query.isPublic || query.isPrivate) {
		config.nsRecs.forEach(function(r) {
			query.addAnswer(query.isPublic ? config.publicBase : config.privateBase, r, 3600);
		});
		server.send(query);
	}
}

Server.prototype.handleResolve = function(query) {
	var domain = query.name();
	var ns = this.ns;

	if (domain === config.publicBase) {
		config.reverseProxy.forEach(function(r) {
			query.addAnswer(config.publicBase, r, 3600);
		});
		ns.send(query);
		return;
	} else if (domain === config.privateBase) {
		ns.send(query);
		return;
	}

	if (query.isPublic || query.isPrivate) {
		var parts = domain.replace("." + (query.isPublic ? config.publicBase : config.privateBase), "").split(".");
		if (parts.length == 1) {
			var host = parts[0];
			this.makeVMRecords(host, query, function(err, recs) {
				if (err) {
					this.makeFileRecords(host, query, function(err, recs) {
						if (err)
							return ns.send(query);
						return ns.sendRecs(query, recs);
					});
				} else {
					return ns.sendRecs(query, recs);
				}
			}.bind(this));
		} else {
			var host = parts.join(".");
			this.makeFileRecords(host, query, function(err, recs) {
				if (err)
					return ns.send(query);
				return ns.sendRecs(query, recs);
			});
		}
	} else {
		ns.send(query);
	}
}

Server.prototype.handleSOA = function(query) {
	var domain = query.name();

	if (domain === config.privateBase || domain === config.publicBase) {

		log.info("soa req from %s", query._client.address);

		var rec = makeSOA(domain);
		query.addAnswer(domain, rec, 60);

		var nsrec = new named.NSRecord(config.hostname + "." + domain);
		query.addAuthority(domain, nsrec, 3600);

		config.myRecs.forEach(function(r) {
			query.addAdditional(config.hostname + "." + domain, r, 3600);
		});

		this.ns.send(query);
	}
}

module.exports = Server;
