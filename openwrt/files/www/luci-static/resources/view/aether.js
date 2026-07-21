/*
 * luci-app-aether — LuCI Web Interface for Aether VPN
 *
 * Uses built-in ubus objects (service / rc / uci / file) instead of a
 * custom shell rpcd handler. On OpenWrt 25.12.5 shell handlers under
 * /usr/libexec/rpcd may register as ubus objects with zero methods.
 */
'use strict';
'require form';
'require rpc';
'require uci';
'require view';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: {}
});

var callRCInit = rpc.declare({
	object: 'rc',
	method: 'init',
	params: [ 'name', 'action' ],
	expect: {}
});

var callUCIGet = rpc.declare({
	object: 'uci',
	method: 'get',
	params: [ 'config', 'section', 'option' ],
	expect: {}
});

var callFileExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ],
	expect: {}
});

function extractFromLogs(logs, pattern) {
	if (!logs) return '';
	var m = logs.match(pattern);
	return m ? m[1] : '';
}

function getServiceStatus() {
	return Promise.all([
		callServiceList('aether').then(function(res) {
			try {
				var inst = res.aether.instances.instance1;
				return { running: !!inst.running, pid: inst.pid, command: inst.command };
			} catch (e) {
				return { running: false };
			}
		}).catch(function() {
			return { running: false };
		}),
		callUCIGet('aether', 'main', 'enabled').then(function(r) {
			return (r && r.value != null) ? String(r.value).replace(/'/g, '') : '0';
		}).catch(function() { return '0'; }),
		callUCIGet('aether', 'main', 'protocol').then(function(r) {
			return (r && r.value) ? String(r.value).replace(/'/g, '') : 'masque';
		}).catch(function() { return 'masque'; }),
		callFileExec('logread', [ '-e', 'aether', '-l', '30' ]).then(function(r) {
			return (r && r.stdout) ? r.stdout : '';
		}).catch(function() { return ''; }),
		callFileExec('/usr/bin/aether', [ '--version' ]).then(function(r) {
			return (r && r.stdout) ? String(r.stdout).trim() : '';
		}).catch(function() { return ''; })
	]).then(function(r) {
		var svc = r[0], logs = r[3], version = r[4];
		return {
			running: svc.running,
			pid: svc.pid,
			command: svc.command,
			enabled: r[1],
			protocol: r[2],
			version: version.replace(/^aether\s+/i, ''),
			endpoint: extractFromLogs(logs, /using cloudflare edge ([0-9.:]+)/),
			transport: extractFromLogs(logs, /MASQUE transport: ([^\s]+)/),
			socks_addr: extractFromLogs(logs, /socks5 (?:server )?listening on ([^\s]+)/),
			obfuscation: extractFromLogs(logs, /obfuscation profile: (\w+)/),
			scan_mode: extractFromLogs(logs, /scan mode: (\w+)/),
			identity: extractFromLogs(logs, /device=([^\s]+)/),
			logs: logs
		};
	});
}

function doServiceAction(action) {
	return function() {
		var btn = this;
		btn.disabled = true;
		btn.value = '...';
		callRCInit('aether', action).then(function() {
			setTimeout(function() { location.reload(); }, 3000);
		}).catch(function() {
			btn.disabled = false;
			btn.value = action.charAt(0).toUpperCase() + action.slice(1);
		});
	};
}

function doTestConnection(host) {
	return function() {
		var btn = this;
		var resultEl = document.getElementById('test-result-' + host);
		btn.disabled = true;
		btn.value = 'Testing...';
		if (resultEl) {
			resultEl.textContent = 'Connecting...';
			resultEl.style.color = '#888';
		}

		var startTime = Date.now();
		callFileExec('/usr/bin/aether-ctl', [ 'test', host ]
		).then(function(r) {
			var elapsed = Date.now() - startTime;
			var output = (r && r.stdout) ? r.stdout : '';
			if (output.indexOf('OK') !== -1) {
				var match = output.match(/HTTP (\d+),\s*([\d.]+)s/);
				var info = match ? 'HTTP ' + match[1] + ' — ' + Math.round(parseFloat(match[2]) * 1000) + 'ms' : 'OK — ' + elapsed + 'ms';
				if (resultEl) {
					resultEl.textContent = info;
					resultEl.style.color = '#2ecc71';
				}
			} else {
				if (resultEl) {
					resultEl.textContent = 'Failed — ' + elapsed + 'ms';
					resultEl.style.color = '#e74c3c';
				}
			}
		}).catch(function() {
			var elapsed = Date.now() - startTime;
			if (resultEl) {
				resultEl.textContent = 'Timeout — ' + elapsed + 'ms';
				resultEl.style.color = '#e74c3c';
			}
		}).finally(function() {
			btn.disabled = false;
			btn.value = host;
		});
	};
}

function fetchLogs() {
	return callFileExec('logread', [ '-e', 'aether', '-l', '40' ]).then(function(r) {
		return (r && r.stdout) ? r.stdout : '(no logs)';
	}).catch(function() {
		return '(failed to read logs)';
	});
}

return view.extend({
	load: function() {
		return {};
	},

	render: function() {
		var el = E('div', {});

		return getServiceStatus().then(function(st) {
			var tbl = E('table', { 'class': 'table' });

			function row(label, val) {
				if (val == null || val === '') return;
				tbl.appendChild(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'style': 'width:160px;font-weight:600' }, label),
					E('td', { 'class': 'td' }, val)
				]));
			}

			var color = st.running ? '#2ecc71' : '#e74c3c';
			row('State', E('span', {
				'style': 'font-weight:bold;color:' + color
			}, st.running ? 'Running' : 'Stopped'));

			if (st.running) {
				if (st.version) row('Version', st.version);
				if (st.pid) row('PID', String(st.pid));
				if (st.endpoint) row('Endpoint', E('code', {}, st.endpoint));
				if (st.transport) row('Transport', 'MASQUE / ' + st.transport);
				if (st.obfuscation) row('Obfuscation', st.obfuscation);
				if (st.scan_mode) row('Scan Mode', st.scan_mode);
				if (st.socks_addr) row('SOCKS5 Proxy', E('code', {}, st.socks_addr));
				if (st.identity) {
					row('Device ID', E('code', {
						'style': 'font-size:11px;word-break:break-all'
					}, st.identity));
				}
			} else {
				row('Info', 'Service is not running. Click Start to begin.');
			}

			var btns = E('div', {
				'style': 'margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap'
			});

			if (st.running) {
				btns.appendChild(E('input', {
					'type': 'button',
					'class': 'cbi-button cbi-button-remove',
					'value': 'Stop',
					'click': doServiceAction('stop')
				}));
				btns.appendChild(E('input', {
					'type': 'button',
					'class': 'cbi-button cbi-button-reset',
					'value': 'Restart',
					'click': doServiceAction('restart')
				}));
			} else {
				btns.appendChild(E('input', {
					'type': 'button',
					'class': 'cbi-button cbi-button-apply',
					'value': 'Start',
					'click': doServiceAction('start')
				}));
			}

			btns.appendChild(E('span', {
				'style': 'font-size:12px;color:#888;margin-left:8px'
			}, 'Start/Stop controls the running tunnel. "Enable on Boot" below controls auto-start on reboot.'));

			el.appendChild(E('div', { 'class': 'cbi-section' }, [
				E('h3', { 'style': 'margin-top:0' }, 'Status'),
				tbl,
				btns
			]));

			// --- Connection Test Section ---
			var testSection = E('div', { 'class': 'cbi-section' }, [
				E('h3', { 'style': 'margin-top:0' }, 'Connection Test'),
				E('p', { 'style': 'margin:4px 0 10px 0;color:#666;font-size:13px' },
					'Test if the tunnel can reach external services through the SOCKS5 proxy.')
			]);

			var testHosts = ['google.com', 'youtube.com', 'github.com', 'telegram.org'];
			var testRow = E('div', {
				'style': 'display:flex;gap:10px;align-items:center;flex-wrap:wrap'
			});

			testHosts.forEach(function(host) {
				var wrapper = E('div', {
					'style': 'display:flex;align-items:center;gap:6px'
				});

				var btn = E('input', {
					'type': 'button',
					'class': 'cbi-button cbi-button-apply',
					'value': host,
					'click': doTestConnection(host)
				});

				var result = E('span', {
					'id': 'test-result-' + host,
					'style': 'font-size:13px;color:#888;min-width:100px'
				}, '');

				wrapper.appendChild(btn);
				wrapper.appendChild(result);
				testRow.appendChild(wrapper);
			});

			testSection.appendChild(testRow);
			el.appendChild(testSection);

			// --- Live Logs Section ---
			var logSection = E('div', { 'class': 'cbi-section' }, [
				E('h3', { 'style': 'margin-top:0' }, 'Live Logs'),
				E('p', { 'style': 'margin:4px 0 10px 0;color:#666;font-size:13px' },
					'Recent Aether log output. Click Refresh to update.')
			]);

			var logContent = E('pre', {
				'style': 'background:#1a1a2e;color:#e0e0e0;padding:12px;border-radius:6px;max-height:400px;overflow-y:auto;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-all;margin:0'
			}, st.logs || '(no logs)');

			var refreshBtn = E('input', {
				'type': 'button',
				'class': 'cbi-button cbi-button-apply',
				'value': 'Refresh',
				'click': function() {
					refreshBtn.disabled = true;
					refreshBtn.value = 'Loading...';
					fetchLogs().then(function(logs) {
						logContent.textContent = logs;
						logContent.scrollTop = logContent.scrollHeight;
					}).finally(function() {
						refreshBtn.disabled = false;
						refreshBtn.value = 'Refresh';
					});
				}
			});

			var logHeader = E('div', {
				'style': 'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px'
			}, [ refreshBtn ]);

			logSection.appendChild(logHeader);
			logSection.appendChild(logContent);
			el.appendChild(logSection);

			el.appendChild(E('hr', {
				'style': 'margin:12px 0;border:none;border-top:1px solid #ddd'
			}));

			var m = new form.Map('aether', '',
				'Configure Aether tunnel settings below. Click "Save & Apply" to persist changes.');
			var s, o;

			s = m.section(form.NamedSection, 'main', 'aether', 'Basic Settings');
			s.anonymous = true;

			o = s.option(form.Flag, 'enabled', 'Enable on Boot',
				'Auto-start Aether when the router boots');
			o.default = '0';
			o.rmempty = false;

			o = s.option(form.ListValue, 'protocol', 'Protocol');
			o.value('masque', 'MASQUE (recommended)');
			o.value('wg', 'WireGuard');
			o.value('gool', 'WARP-in-WARP');
			o.default = 'masque';

			o = s.option(form.Value, 'socks_listen', 'SOCKS5 Listen Address');
			o.default = '0.0.0.0:1819';
			o.datatype = 'ipaddrport';
			o.rmempty = false;

			s = m.section(form.NamedSection, 'main', 'aether', 'Network');

			o = s.option(form.ListValue, 'scan_mode', 'Scan Mode',
				'turbo=fastest, balanced=default, thorough=best quality, stealth=quietest, ironclad=real tunnel test');
			o.value('turbo', 'Turbo');
			o.value('balanced', 'Balanced (default)');
			o.value('thorough', 'Thorough');
			o.value('stealth', 'Stealth');
			o.value('ironclad', 'Ironclad (real tunnel test)');
			o.default = 'balanced';

			o = s.option(form.ListValue, 'ip_version', 'IP Version');
			o.value('ipv4', 'IPv4 only');
			o.value('ipv6', 'IPv6 only');
			o.value('both', 'Both');
			o.default = 'ipv4';

			o = s.option(form.Value, 'peer', 'Force Peer',
				'ip:port, or leave empty for auto-scan');
			o.rmempty = true;

			s = m.section(form.NamedSection, 'main', 'aether', 'Obfuscation');

			o = s.option(form.ListValue, 'obfuscation_profile', 'Profile');
			o.value('off', 'Off');
			o.value('light', 'Light');
			o.value('firewall', 'Firewall (recommended)');
			o.value('balanced', 'Balanced');
			o.value('gfw', 'GFW');
			o.value('aggressive', 'Aggressive');
			o.default = 'firewall';

			o = s.option(form.Flag, 'http2_mode', 'HTTP/2 Mode',
				'Enable if UDP/QUIC is blocked');
			o.default = '0';
			o.depends('protocol', 'masque');

			o = s.option(form.Value, 'h2_peer', 'H2 Peer',
				'Manual destination for h2 mode (ip:port), leave empty for auto');
			o.rmempty = true;
			o.depends('http2_mode', '1');

			o = s.option(form.Flag, 'fragment_tls', 'TLS Fragmentation',
				'Fragment ClientHello (HTTP/2 only)');
			o.default = '0';
			o.depends('http2_mode', '1');

			o = s.option(form.Value, 'fragment_size', 'Fragment Size');
			o.default = '16-32';
			o.depends('fragment_tls', '1');

			o = s.option(form.Value, 'fragment_delay', 'Fragment Delay (ms)');
			o.default = '2-10';
			o.depends('fragment_tls', '1');

			s = m.section(form.NamedSection, 'main', 'aether', 'Advanced');

			o = s.option(form.ListValue, 'log_level', 'Log Level');
			o.value('error', 'Error');
			o.value('warn', 'Warning');
			o.value('info', 'Info');
			o.value('debug', 'Debug');
			o.default = 'info';

			o = s.option(form.Value, 'keepalive', 'Keepalive (s)');
			o.default = '5';
			o.datatype = 'min(1)';
			o.depends('protocol', 'wg');
			o.depends('protocol', 'gool');

			o = s.option(form.Value, 'reconnect_secs', 'Reconnect Delay (s)',
				'Delay before auto-reconnect after tunnel drops');
			o.default = '2';
			o.datatype = 'min(1)';

			o = s.option(form.Value, 'validate_secs', 'Validation Timeout (s)',
				'Seconds to wait for data-plane probe before giving up on a gateway');
			o.default = '10';
			o.datatype = 'min(1)';

			o = s.option(form.Flag, 'quick_reconnect', 'Quick Reconnect',
				'Always reuse last known-good gateway without asking');
			o.default = '0';

			o = s.option(form.Flag, 'no_data_check', 'Skip Data Validation',
				'Trust gateway after handshake only (faster but less reliable)');
			o.default = '0';

			o = s.option(form.Value, 'config_path', 'Config Path');
			o.default = '/etc/aether/aether.toml';
			o.readonly = true;

			return m.render().then(function(formNode) {
				el.appendChild(formNode);
				return el;
			});
		});
	}
});
