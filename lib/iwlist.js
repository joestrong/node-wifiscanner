var exec = require('child_process').exec;
var util = require('util');
var linuxProvider = '/sbin/iwlist';

function parseIwlist(str) {
    var out = str.replace(/^\s+/mg, '');
    out = out.split('\n');
    var cells = [];
    var line;
    var info = {};
    var fields = {
        'mac' : /^Cell \d+ - Address: (.*)/,
        'ssid' : /^ESSID:"(.*)"/,
        'channel': /^Channel:(.*)/,
        // 'protocol' : /^Protocol:(.*)/,
        // 'mode' : /^Mode:(.*)/,
        // 'frequency' : /^Frequency:(.*)/,
        'encryption_key' : /Encryption key:(.*)/,
        // 'bitrates' : /Bit Rates:(.*)/,
        'quality' : /Quality(?:=|\:)([^\s]+)/,
        'signal_level' : /Signal level(?:=|\:)([-\w]+)/
    };
    var wpa2match = /IEEE 802\.11i\/(WPA2) Version /;
    var wpa1match = /(WPA) Version /;

    for (var i=0,l=out.length; i<l; i++) {
        line = out[i].trim();

        if (!line.length) {
            continue;
        }
        if (line.match("Scan completed :")) {
            continue;
        }
        if (line.match("Interface doesn't support scanning.")) {
            continue;
        }

        if (line.match(fields.mac)) {
            cells.push(info);
            info = {};
        }

        for (var field in fields) {
            if (line.match(fields[field])) {
                info[field] = (fields[field].exec(line)[1]).trim();
            }
        }
        
        // Encryption type match
        if (line.match(wpa2match)) {
            info['encryption_type'] = 'WPA2';
        }
        if (!info['encryption_type'] && line.match(wpa1match)) {
            info['encryption_type'] = 'WPA';
        }
    }
    cells.push(info);
    cells.shift();
    return cells;
}

function scan(callback) {
    var new_env = util._extend(process.env, { LANG: "en", maxBuffer: 1024 * 1000 });
    exec(linuxProvider + ' scan', new_env, function (err, stdout, stderr) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, parseIwlist(stdout));
    });
}

exports.scan = scan;
exports.utility = linuxProvider;
