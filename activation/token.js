var debug = require('debug')('as:token');
const https = require('https');
const fetch = require('node-fetch');

var database = require('../util/database.js');
const config = require('../config.js');
const error = require('../util/utils.js').error;

const httpsAgent = new https.Agent({
    rejectUnauthorized: config.ar_ssl,
});

// Forward token request to AR
//
async function forward_token(req, res) {
    debug('Forward request to /token endpoint of AR');
    if ( !req.body.client_id) {
	debug("Missing parameter client_id");
	error(400, "Missing parameter client_id", res);
	return null;
    }
    let eori = req.body.client_id;

    // Proxy request to AR
    let token = {};
    try {
	const tparams = new URLSearchParams(req.body);
	const options = {
            method: 'POST',
            body: tparams,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
	}
	if(config.ar_token.toLowerCase().startsWith("https://")) {
		options.agent = httpsAgent;
	}
	const ar_response = await fetch(config.ar_token, options);
	const res_body = await ar_response.json();
	if (ar_response.status != 200) {
	    debug('Wrong status code in response: %o', res_body);
	    res.status(ar_response.status).send(res_body);
	    return null;
	}
	if ( !res_body.access_token || !res_body.expires_in) {
	    debug('Invalid response: %o', res_body);
	    error(400, "Received invalid response from AR: " + JSON.stringify(res_body), res);
	    return null;
	}
	token = {
	    eori: eori,
	    access_token: res_body.access_token,
	    expires: Date.now() + (1000*res_body.expires_in)
	};
	debug('Received response: %o', res_body);
	return {
	    token: token,
	    response: res_body
	};
    } catch (e) {
	console.error(e);
	let msg = e;
	if (e.response) {
	    msg = e.response.text();
	}
	error(500, "Error when forwarding request to AR: " + msg, res);
	return null;
    }
}

// Perform token request
//
async function performToken(req, res, db) {

    // Forward token request to AR
    const token = await forward_token(req, res);
    if ( !token ) {
	return null;
    }
    
    // DB entry insert
    const ins_err = await database.insertToken(token.token, db);
    if (ins_err) {
	error(500, "Could not insert token into DB: " + ins_err, res);
	return null;
    }

    return token;    
}

module.exports = {
    performToken: performToken
};
