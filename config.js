const fs = require('fs');
const yaml = require('js-yaml');

var user_cfg = {}
try {
    let config_file = './config/as.yml';
    console.log("Loading config: ", config_file);
    let fileContents = fs.readFileSync(config_file, 'utf8');
    user_cfg = yaml.load(fileContents);
} catch (e) {
    console.error("Error loading as.yml: ", e);
    process.exit(1)
}

let config = {};

// Default values
config.key = "";
config.crt = "";
config.id = "EU.EORI.NLPACKETDEL";
config.port = 7000;
config.url = "http://localhost:7000";
config.db_source = ":memory:"; //"db.sqlite";
config.ar_token = "http://localhost/connect/token";
config.ar_policy = "http://localhost/policy";
config.ar_delegation = "http://localhost/delegation";
config.ar_id = "EU.EORI.NL000000004";
config.ar_ssl = false;

// Client data
if (user_cfg.client) {
    if (user_cfg.client.id) {
	config.id = user_cfg.client.id;
    }
    config.key = user_cfg.client.key;
    config.crt = user_cfg.client.crt;
}

// Database
if (user_cfg.db) {
    if (user_cfg.db.source) {
	config.db_source = user_cfg.db.source;
    }
}

// Authorisation registry
if (user_cfg.ar) {
    if (user_cfg.ar.token) {
	config.ar_token = user_cfg.ar.token;
    }
    if (user_cfg.ar.policy) {
	config.ar_policy = user_cfg.ar.policy;
    }
    if (user_cfg.ar.id) {
	config.ar_id = user_cfg.ar.id;
    }
    if (user_cfg.ar.delegation) {
	config.ar_delegation = user_cfg.ar.delegation
    }
    if (user_cfg.ar.rejectUnauthorized) {
	config.ar_ssl = user_cfg.ar.rejectUnauthorized;
    }
}

module.exports = config;
