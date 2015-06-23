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

var common = require('./common');
var config = require('./config');
var named = require('named');
var async = require('async');

function addStatic(isPrivate, zones, cb) {
	var server = this;
	var recs = isPrivate ? zones[config.privateBase] : zones[config.publicBase];
	var zone = isPrivate ? server.privateZone : server.publicZone;
	if (zone.cname)
		zone.cname.forEach(function(r) {
			var alias = r.alias;
			if (alias === "@" || alias === "@.")
				alias = config.publicBase + ".";

			if (alias.endsWith("."))
				alias = alias.slice(0, -1);
			else
				alias = alias + "." + (isPrivate ? config.privateBase : config.publicBase);

			recs.add(r.name, new named.CNAMERecord(alias));
		});
	if (zone.a)
		zone.a.forEach(function(r) {
			recs.add(r.name, new named.ARecord(r.ip));
		});
	if (zone.aaaa)
		zone.aaaa.forEach(function(r) {
			recs.add(r.name, new named.AAAARecord(r.ip));
		});
	delete recs['@'];
	delete recs['IN'];
	return cb(null);
}

function addServers(zones, cb) {
	var server = this;
	var pubZone = zones[config.publicBase];
	var privZone = zones[config.privateBase];
	server.cnapi.listServers(function(err, svrs) {
		if (err)
			return cb(err);

		async.each(svrs, function(svr, svrcb) {
			server.napi.listNics({"belongs_to_uuid": svr.uuid}, function(err, nics) {
				if (err)
					svrcb(err);
				nics.forEach(function(nic) {
					if (nic.ip) {
						/* forward records */
						pubZone.add(svr.uuid, new named.ARecord(nic.ip));
						pubZone.add(svr.hostname, new named.ARecord(nic.ip));
						privZone.add(svr.uuid, new named.ARecord(nic.ip));
						privZone.add(svr.hostname, new named.ARecord(nic.ip));
						/* reverse records */
						var parts = nic.ip.split(".").reverse();
						var revzone = parts.slice(1).join(".") + ".in-addr.arpa";
						if (zones[revzone] === undefined)
							zones[revzone] = new common.recs(revzone);
						zones[revzone].add(parts[0], new named.PTRRecord(svr.hostname + "." + config.privateBase));
					}
				});
				svrcb();
			});
		}, cb);
	});
}

function addVms(zones, cb) {
	var server = this;
	var pubZone = zones[config.publicBase];
	var privZone = zones[config.privateBase];
	var userCache = {};
	server.vmapi.listVms({state: "active", fields: common.vmFields}, function(err, vms) {
		if (err)
			return cb(err);

		async.each(vms, function(vm, vmcb) {
			if (vm.destroyed)
				return vmcb(null);
			if (vm.state === "failed")
				return vmcb(null);

			var afterUser = function(user) {
				server.namesDb.find({ alias: vm.alias }, function(err, docs) {
					var doAlias = false;
					if (docs.length > 0) {
						var doc = docs[0];
						if (doc.owner_uuid === vm.owner_uuid)
							doAlias = true;
					} else {
						server.namesDb.insert({ alias: vm.alias, owner_uuid: vm.owner_uuid });
						doAlias = true;
					}
					var z = user.login + '-' + vm.alias;
					pubZone.set(z, []);
					privZone.set(z, []);
					var trec = new named.TXTRecord(vm.uuid + '@' + vm.server_uuid);
					var needsCname = true;
					vm.nics.forEach(function(nic) {
						/* forward records */
						var arec = new named.ARecord(nic.ip);

						privZone.add(z, arec);
						if (doAlias)
							privZone.add(vm.alias, arec);

						if (!common.isRFC1918(nic.ip)) {
							pubZone.add(z, arec);
							if (doAlias)
								pubZone.add(vm.alias, arec);
							needsCname = false;
						}
						/* reverse records */
						var parts = nic.ip.split(".").reverse();
						var revzone = parts.slice(1).join(".") + ".in-addr.arpa";
						if (zones[revzone] === undefined)
							zones[revzone] = new common.recs(revzone);
						zones[revzone].add(parts[0], new named.PTRRecord(z + "." + config.privateBase));
					});
					if (needsCname) {
						var rec = new named.CNAMERecord(config.publicBase);
						pubZone.set(z, [rec]);
						if (doAlias)
							pubZone.set(vm.alias, [rec]);
					}
					privZone.add(z, trec);
					if (doAlias)
						privZone.add(vm.alias, trec);
					return vmcb(null);
				});
			};

			if (userCache[vm.owner_uuid])
				afterUser(userCache[vm.owner_uuid]);
			else
				server.ufds.getUser(vm.owner_uuid, function(err, owner) {
					if (err)
						return vmcb(err);
					if (!owner)
						return vmcb(null);
					userCache[vm.owner_uuid] = owner;
					afterUser(owner);
				});

		}, cb);
	});
}

function makeAllRecs(acb) {
	var zones = {};
	zones[config.privateBase] = new common.recs(config.privateBase);
	zones[config.publicBase] = new common.recs(config.publicBase);
	async.series([
		addStatic.bind(this, true, zones),
		addStatic.bind(this, false, zones),
		addServers.bind(this, zones),
		addVms.bind(this, zones)
	], function(err) {
		if (err)
			return acb(err);
		return acb(null, zones);
	});
}

module.exports = {
	makeRecords: makeAllRecs
}
