var debug = require('debug')('as:server');
const moment = require('moment');
const uuid = require('uuid');
const fetch = require('node-fetch');
const https = require('https');
const jose = require('node-jose');
var jwt = require('jsonwebtoken');
var bodyParser = require('body-parser');
const express = require('express');
const app = express();

var database = require('./util/database.js');
const config = require('./config.js');
const error = require('./util/utils.js').error;
const performToken = require('./activation/token.js').performToken;
const performCreatePolicy = require('./activation/createPolicy.js').performCreatePolicy;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const httpsAgent = new https.Agent({
    rejectUnauthorized: config.ar_ssl,
});
let db = null;
let chain = [];

// Init server
// 
async function init() {
    debug('Initialising server...');
    // Prepare DB
    db = await database.openDB();
    
    // Prepare CRT
    const crt_regex = /^-----BEGIN CERTIFICATE-----\n([\s\S]+?)\n-----END CERTIFICATE-----$/gm;
    let m;
    while ((m = crt_regex.exec(config.crt)) !== null) {
	// This is necessary to avoid infinite loops with zero-width matches
	if (m.index === crt_regex.lastIndex) {
            crt_regex.lastIndex++;
	}
	chain.push(m[1].replace(/\n/g, ""));
    }
}

// /token
// Proxy request to /token endpoint of AR
// and store returned token
app.post('/token', async (req, res) => {
    debug('Received request at /token endpoint');
    const token = await performToken(req, res, db);

    // Return AR response
    if (token) {
	debug('Received access_token with response: %o', token.response);
	debug('==============');
	res.send(token.response);
    }
});


// /createpolicy
// Create policy at AR
// Perform additional activation steps if needed
app.post('/createpolicy', async (req, res) => {
    debug('Received request at /createpolicy endpoint');
    // Create requested policy at AR
    const presult = await performCreatePolicy(req, res, db, chain);

    // **********************
    // Other activation steps (e.g. starting computation nodes)
    // could be added here!
    // **********************

    // Return result
    if (presult) {
	debug('Successfully created new policy at AR. Received policy_token: %o', presult.policy_token);
	debug('==============');
	res.send({
	    policy_token: presult.policy_token
	});
    }
});

// /health
// Healthcheck endpoint
app.get('/health', (req, res) => {
    res.send({
	uptime: process.uptime(),
	message: 'OK',
	timestamp: Date.now()
    });
})

// Start server
//
const server = app.listen(config.port, () => {
    console.log(`Express running → PORT ${server.address().port}`);
    init();
});
