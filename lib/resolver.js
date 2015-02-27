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
var bunyan = require('bunyan');
var async = require('async');
var zonefile = require('dns-zonefile');
var config = require('./config');
var common = require('./common');

var log = bunyan.createLogger({name: 'zone-dns-resolver'});

var resolver = {};

resolver.makeVMRecords = function(host, query, cb) {
	if (!this.ufdsConnected)
		return cb("UFDS not connected yet");

	var recs = new common.recs();

	var parts = host.split("-");
	var user = parts[0];
	var alias = parts.slice(1).join("-");

	findVm(this, user, alias, function(err, vm) {
		if (err)
			return cb(err);

		switch (query.type()) {
			case 'A':
				var nets = vm.nics;
				var addRevProxy = true;
				for (var i = 0; i < nets.length; ++i) {
					if (query.isPrivate ||
							(query.isPublic && !common.isRFC1918(nets[i].ip))) {
						var rec = new named.ARecord(nets[i].ip);
						recs.add(host, rec);
						addRevProxy = false;
					}
				}
				if (addRevProxy) {
					var crec = new named.CNAMERecord(config.publicBase);
					recs.add(host, crec);
					config.reverseProxy.forEach(function(r) {
						recs.add(config.publicBase + ".", r);
					});
				}
				break;
			case 'TXT':
				var rec = new named.TXTRecord(vm.uuid + '@' + vm.server_uuid);
				recs.add(host, rec)
				break;
		}

		return cb(null, recs);
	});
};

resolver.makeFileRecords = function(host, query, cb) {
	var zone = query.isPrivate ? this.privateZone : this.publicZone;
	var domain = host + "." + (query.isPrivate ? config.privateBase : config.publicBase);
	var proto = {};
	var recs = new common.recs();

	if (zone.cname)
		for (var i = 0; i < zone.cname.length; ++i) {
			if (matches(zone.cname[i].name, domain, host)) {
				var tgt = zone.cname[i].alias;
				if (tgt === "@")
					tgt = config.publicBase;

				var rec = new named.CNAMERecord(tgt);
				recs.add(host, rec);

				if (tgt === config.publicBase)
					config.reverseProxy.forEach(function(r) {
						recs.add(config.publicBase + ".", r);
					});

				return cb(null, recs);
			}
		}
	if (zone.a)
		for (var i = 0; i < zone.a.length; ++i) {
			if (matches(zone.a[i].name, domain, host)) {
				var rec = new named.ARecord(zone.a[i].ip);
				recs.add(host, rec);
			}
		}
	if (zone.aaaa)
		for (var i = 0; i < zone.aaaa.length; ++i) {
			if (matches(zone.aaaa[i].name, domain, host)) {
				var rec = new named.AAAARecord(zone.aaaa[i].ip);
				recs.add(host, rec);
			}
		}

	cb(null, recs);
};

function findVm(srv, user, alias, cb) {
	if (user) {
		srv.ufds.getUser(user, function(err, userObj) {
			if (err)
				return findVm(srv, null, user + "-" + alias, cb);
			var uuid = userObj.uuid;
			srv.vmapi.listVms({owner_uuid: uuid, alias: alias}, function(err, vms) {
				if (err)
					return cb(err);
				vms = vms.filter(common.vmFilter);
				if (vms.length === 1) {
					var vm = vms[0];
					return cb(undefined, vm);
				} else if (vms.length > 0) {
					return cb("Duplicate VM alias");
				} else {
					return cb("No VMs found for user");
				}
			});
		});
	} else {
		srv.vmapi.listVms({alias: alias}, function(err, vms) {
			if (err)
				return cb(err);
			vms = vms.filter(common.vmFilter);
			if (vms.length === 1 && vms[0].alias === alias) {
				var vm = vms[0];
				cb(undefined, vm);
				srv.namesDb.find({ alias: alias }, function(err, docs) {
					if (err || docs.length < 1)
						srv.namesDb.insert({ alias: alias, owner: vm.owner_uuid });
				});
			} else if (vms.length > 1) {
				srv.namesDb.find({ alias: alias }, function(err, docs) {
					if (err)
						return err;
					if (docs.length === 0)
						return cb("Duplicate alias and no names records found");
					var doc = docs[0];
					var matchVms = vms.filter(function(vm) { return (vm.owner_uuid === doc.owner_uuid); });
					if (matchVms.length < 1)
						return cb("No VMs matching names db record");
					var vm = matchVms[0];
					return cb(undefined, vm);
				});
			} else {
				return cb("No VMs found");
			}
		});
	}
}

function matches(zoneName, domain, host) {
	if (zoneName === domain)
		return true;
	if (zoneName === host)
		return true;
	if (zoneName === domain + ".")
		return true;
	var parts = zoneName.split(".");
	var ourparts = host.split(".");
	var len = (parts.length > ourparts.length) ? parts.length : ourparts.length;
	for (var i = 0; i < len; ++i) {
		if (parts[i] !== "*" && parts[i] !== ourparts[i])
			return false;
	}
	return true;
}

module.exports = resolver;
