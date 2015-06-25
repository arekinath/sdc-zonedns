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
var Datastore = require('nedb');

var log = bunyan.createLogger({name: 'zone-dns', level: 'debug'});

var config = require('./config');
var slaver = require('./slaver');
var common = require('./common');

String.prototype.endsWith = function(suffix) {
	return this.indexOf(suffix, this.length - suffix.length) !== -1;
};

String.prototype.startsWith = function (str){
	return this.indexOf(str) == 0;
};

function Server() {
	this.ufdsConnected = false;
	this.log = log;

	this.privateZone = zonefile.parse(fs.readFileSync(config.privateZoneFile, 'utf8'));
	if (config.publicZoneFile)
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

	this.makeRecords = slaver.makeRecords;

	this.namesDb = new Datastore({ filename: config.namesDbPath, autoload: true });

	this.zones = {};
	this.soaRecs = {};
	this.soaRecs[config.privateBase] = makeSOA(config.privateBase);
	this.soaRecs[config.publicBase] = makeSOA(config.publicBase);

	setTimeout(updateRecs.bind(this), 0);
}

function updateRecs() {
	var self = this;
	this.makeRecords(function(err, zones) {
		setTimeout(updateRecs.bind(self), 12000);
		if (err) {
			log.error("zones failed to build: %j", err);
			return;
		}
		if (Object.keys(zones[config.privateBase]).length < 5) {
			log.error("private zone is too short: %j", Object.keys(zones[config.privateBase]));
			return;
		}
		if (Object.keys(zones[config.publicBase]).length < 5) {
			log.error("public zone is too short: %j", Object.keys(zones[config.publicBase]));
			return;
		}
		Object.keys(zones).forEach(function(z) {
			if (!common.deepCompare(zones[z], self.zones[z])) {
				log.debug("rebuilt zone %s with %d names ok", z, Object.keys(zones[z]).length);
				self.zones[z] = zones[z];
				self.soaRecs[z] = makeSOA(z);
			}
		});

	});
}

Server.prototype.handleQuery = function(query) {
	var domain = query.name();
	var type = query.type();
	var log = this.log;
	var self = this;

	var zone;
	Object.keys(this.zones).forEach(function(z) {
		if (domain.endsWith(z)) {
			zone = self.zones[z];
		}
	});

	if (zone === undefined) {
		/* return empty, we have no zone that matches this query */
		return this.ns.send(query);
	}

	switch (type) {
		case 'AXFR':
			return this.handleAXFR(query, zone);

		case 'NS':
			return this.handleNS(query, zone);

		case 'A':
		case 'TXT':
		case 'PTR':
		case 'SRV':
			return this.handleResolve(query, zone);

		case 'SOA':
			return this.handleSOA(query, zone);

		default:
			log.info("got unsupported req type %j from %s", type, query._client.address);
			break;
	}
}

function makeSOA(domain) {
	var now = new Date();
	var serial = now.getYear();
	serial = serial * 12 + now.getMonth();
	serial = serial * 31 + now.getDate() - 1;
	serial = serial * 24 + now.getHours();
	serial = serial * 60 + now.getMinutes();
	serial = serial * 4 + Math.floor(now.getSeconds() / 15);
	serial = serial + 0x80008800;
	return new named.SOARecord(config.hostname + "." + config.privateBase, {
		serial: serial,
		admin: config.hostmaster,
		refresh: 60,
		retry: 60,
		expire: 181440,
		ttl: 60
	});
}

function sendRecs(query, recs) {
	var domain = query.name();
	recs.forEach(function(rec) {
		query.addAnswer(domain, rec, config.ttl);
	});

	this.send(query);
}

Server.prototype.handleAXFR = function(query, zone) {
	var domain = query.name();

	log.info("making axfr for %s", query._client.address);

	var soa = this.soaRecs[zone.base];
	query.addAnswer(domain, soa, 60);
	this.ns.send(query);

	config.nsRecs.forEach(function(r) {
		query.addAnswer(domain, r, 3600);
	});
	if (zone.base === config.publicBase) {
		config.reverseProxy.forEach(function(r) {
			query.addAnswer(domain, r, 3600);
		});
	}
	this.ns.send(query);

	var ns = this.ns;

	var i = 0;
	Object.keys(zone).forEach(function(k) {
		if (zone[k] && zone[k].length > 0) {
			zone[k].forEach(function(rec) {
				query.addAnswer(k + "." + zone.base, rec, config.ttl);
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
}

Server.prototype.handleNS = function(query, zone) {
	var domain = query.name();
	if (domain === zone.base) {
		config.nsRecs.forEach(function(r) {
			query.addAnswer(domain, r, 3600);
		});
		this.ns.send(query);
	} else {
		query.setError('enoname');
		this.ns.send(query);
	}
}

Server.prototype.handleResolve = function(query, zone) {
	var domain = query.name();
	var ns = this.ns;

	if (domain === config.publicBase) {
		config.reverseProxy.forEach(function(r) {
			query.addAnswer(config.publicBase, r, 3600);
		});
		config.nsRecs.forEach(function(r) {
			query.addAuthority(zone.base, r, 3600);
		});
		ns.send(query);
		return;
	} else if (domain === config.privateBase) {
		var soa = this.soaRecs[zone.base];
		query.addAuthority(zone.base, soa, 60);
		query.setError('enoname');
		ns.send(query);
		return;
	}

	var subdomain = domain.replace("." + zone.base, "");
	var recs = zone.lookup(subdomain);
	var type = named[query.type() + 'Record'];
	recs = recs.filter(function(r) { return (r instanceof type) || (r instanceof named.CNAMERecord); });
	if (recs.length > 0) {
		config.nsRecs.forEach(function(r) {
			query.addAuthority(zone.base, r, 3600);
		});
		return ns.sendRecs(query, recs);
	} else {
		var soa = this.soaRecs[zone.base];
		query.addAuthority(zone.base, soa, 60);
		query.setError('enoname');
		return ns.send(query);
	}
}

Server.prototype.handleSOA = function(query, zone) {
	var domain = query.name();

	if (domain !== zone.base)
		return this.ns.send(query);

	var soa = this.soaRecs[zone.base];

	query.addAnswer(domain, soa, 60);

	config.nsRecs.forEach(function(r) {
		query.addAuthority(zone.base, r, 3600);
	});

	var nsrec = new named.NSRecord(config.hostname + "." + domain);
	query.addAuthority(domain, nsrec, 3600);

	config.myRecs.forEach(function(r) {
		query.addAdditional(config.hostname + "." + domain, r, 3600);
	});

	this.ns.send(query);
}

module.exports = Server;
