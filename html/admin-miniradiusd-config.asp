<!DOCTYPE html>
<!--
	Tomato GUI
	Copyright (C) 2006-2007 Jonathan Zarate
	http://www.polarcloud.com/tomato/
	For use with Tomato Firmware only.
	No part of this file may be used without permission.
	LAN Access admin module by Augusto Bott
-->
<html lang="en-GB">
<head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<meta name="robots" content="noindex,nofollow">
<title>[<% ident(); %>] Advanced: RADIUS Config</title>
<link rel="stylesheet" type="text/css" href="tomato.css">
<% css(); %>
<script src="tomato.js"></script>
<script src="wireless.jsx?_http_id=<% nv(http_id); %>"></script>

<script>

//	<% nvram ("miniradiusd_users,miniradiusd_en,miniradiusd_secret,miniradiusd_key,miniradiusd_cert");%> 

var cprefix = 'miniradiusd_config';

var la = new TomatoGrid();
la.setup = function() {
	this.init('radiusd-cfg-grid', 'sort', 50, [
	{ type: 'text', maxlen: 32 },
	{ type: 'text', maxlen: 32, type: 'password' }]);
	this.headerSet(['User', 'Password']);

	var r = nvram.miniradiusd_users.split(' ');
	for (var i = 0; i < r.length; ++i) {
		if(r[i].length) {
			var l = r[i].split(':');
			la.insertData(-1, [ l[0], l[1] ] );
		}
	}

	la.recolor();
	la.showNewEditor();
	la.resetNewEditor();
}

la.sortCompare = function(a, b) {
	var da = a.getRowData();
	var db = b.getRowData();
	var r;

	r = cmpText(da[0], db[0]);

	return this.sortAscending ? r : -r;
}

la.resetNewEditor = function() {
	var f = fields.getAll(this.newEditor);
	f[0].value='';
	f[1].value='';
	ferror.clearAll(fields.getAll(this.newEditor));
}

la.verifyFields = function(row, quiet) {
	// TODO: non empty password, different users, bad characters
	var f = fields.getAll(row);

	f[0].value = f[0].value.trim();
	f[1].value = f[1].value.trim();

	if(f[0].value == f[1].value) {
		var m = 'Source and Destination interfaces must be different';
		ferror.set(f[0], m, quiet);
		ferror.set(f[1], m, quiet);
		return 0;
	}
	ferror.clear(f[0]);
	ferror.clear(f[1]);

	if ((f[0].value.length) && (!v_iptaddr(f[0], quiet))) return 0;
	if ((f[1].value.length) && (!v_iptaddr(f[1], quiet))) return 0;

	ferror.clear(f[0]);
	ferror.clear(f[1]);

	f[0].value = f[0].value.replace(/>/g, '_');

	return 1;
}

la.dataToView = function(data) {
	return [data[0], data[1].replace(/./g, '&#x25CF;') ];
}

la.dataToFieldValues = function (data) {
	return [data[0], data[1] ];
}

la.fieldValuesToData = function(row) {
	var f = fields.getAll(row);
	return [f[0].value, f[1].value ];
}

function verifyFields(focused, quiet) {
	 //  TODO
 	// Check presence of keys if enabled..
	 var ok = 1;
	 return ok;
}

function save() {
	if (la.isEditing()) return;
	la.resetNewEditor();

	var fom = E('t_fom');
	var ladata = la.getAllData();

	var s = '';
	for (var i = 0; i < ladata.length; ++i) {
		if (s)
		  s += ' '
		s += ladata[i][0] + ':' + ladata[i][1];
	}

	fom.miniradiusd_users.value = s;
	fom.miniradiusd_en.value = fom._f_miniradiusd_en.checked ? 1 : 0;

	form.submit(fom, 0);
}

function init() {
	la.setup();
	var c;
	if (((c = cookie.get(cprefix + '_notes_vis')) != null) && (c == '1')) {
		toggleVisibility(cprefix, "notes");
	}
}
</script>
</head>

<body onload="init()">
<form id="t_fom" method="post" action="tomato.cgi">
<table id="container">
<tr><td colspan="2" id="header">
	<div class="title">FreshTomato</div>
	<div class="version">Version <% version(); %> on <% nv("t_model_name"); %></div>
</td></tr>
<tr id="body"><td id="navi"><script>navi()</script></td>
<td id="content">
<div id="ident"><% ident(); %></div>

<!-- / / / -->

<input type="hidden" name="_nextpage" value="admin-miniradiusd-config.asp">
<input type="hidden" name="_nextwait" value="20">
<input type="hidden" name="_service" value="miniradiusd-restart">
<input type="hidden" name="miniradiusd_en">
<input type="hidden" name="miniradiusd_users">

<!-- / / / -->

<div class="section-title">RADIUS Config</div>
<div class="section">
	<script>
		createFieldTable('', [
			{ title: 'Enable', name: 'f_miniradiusd_en', type: 'checkbox', value: nvram.miniradiusd_en == 1 },
			{ title: 'Shared secret', name: 'miniradiusd_secret', type: 'text', maxlen: 32, value: nvram.miniradiusd_secret },
			{ title: 'Private key (pem)', name: 'miniradiusd_key', type: 'textarea', value: nvram.miniradiusd_key },
			{ title: 'Certificate (pem)', name: 'miniradiusd_cert', type: 'textarea', value: nvram.miniradiusd_cert }
		]);
	</script>
</div>

<div class="section-title">RADIUS Users</div>
<div class="section">
	<div class="tomato-grid" id="radiusd-cfg-grid"></div>
</div>

<!-- / / / -->

<div class="section-title">Notes <small><i><a href="javascript:toggleVisibility(cprefix,'notes');"><span id="sesdiv_notes_showhide">(Show)</span></a></i></small></div>
<div class="section" id="sesdiv_notes" style="display:none">
	<ul>
		<li>The private key must not be encrypted</li>
	</ul>
</div>

<!-- / / / -->

<div id="footer">
	<span id="footer-msg"></span>
	<input type="button" value="Save" id="save-button" onclick="save()">
	<input type="button" value="Cancel" id="cancel-button" onclick="reloadPage();">
</div>

</td></tr>
</table>
</form>
</body>
</html>
