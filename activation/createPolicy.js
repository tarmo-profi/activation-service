var debug = require('debug')('as:createPolicy');
const https = require('https');
const fetch = require('node-fetch');
const moment = require('moment');
const uuid = require('uuid');
const jose = require('node-jose');
var jwt = require('jsonwebtoken');

var database = require('../util/database.js');
const config = require('../config.js');
const error = require('../util/utils.js').error;

const httpsAgent = new https.Agent({
    rejectUnauthorized: config.ar_ssl,
});

// Creates JWT for obtaining token at AR
//
async function createJwt(chain) {
    const now = moment();
    const iat = now.unix();
    const exp = now.add(30, 'seconds').unix();
    const payload = {
	jti: uuid.v4(),
	iss: config.id,
	sub: config.id,
	aud: [
	    config.ar_id,
	    config.ar_token
	],
	iat,
	nbf: iat,
	exp
    };
    const key = await jose.JWK.asKey(config.key, "pem");
    return await jose.JWS.createSign({
        algorithm: 'RS256',
        format: 'compact',
        fields: {
            typ: "JWT",
            x5c: chain
        }
    }, key).update(JSON.stringify(payload)).final();
}

// Get token from AR
//
async function getToken(chain) {
    debug('Obtaining token from AR');
    const jwtoken = await createJwt(chain);
    let access_token = null;
    try {
	const tparams = new URLSearchParams();
	tparams.append('grant_type', 'client_credentials');
	tparams.append('scope', 'iSHARE');
	tparams.append('client_id', config.id);
	tparams.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
	tparams.append('client_assertion', jwtoken);
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
	    return JSON.stringify(res_body);
	}
	if ( !res_body.access_token) {
	    debug('access_token not found in response: %o', res_body);
	    return "Received invalid response from AR: " + JSON.stringify(res_body);
	}
	return res_body.access_token;
    } catch (e) {
	console.error(e);
	let msg = "General error when obtaining token from AR";
	if (e.response) {
	    msg = msg += ": " + e.response.text();
	}
	return msg;
    }
}

// Build delegation payload
//
async function getDelegationEvidence(eori) {
    let payload = {
	delegationRequest: {
	    policyIssuer: config.id,
	    target: {
		accessSubject: eori
	    },
	    policySets: [
		{
		    policies: [
			{
			    target: {
				resource: {
				    type: "delegationEvidence",
				    identifiers: [
					"*"
				    ],
				    attributes: [
					"*"
				    ]
				},
				actions: [
				    "POST"
				]
			    },
			    rules: [
				{
				    "effect": "Permit"
				}
			    ]
			}
		    ]
		}
	    ]
	}
    };
    return payload;
}

// Check for delegation evidence if sender is allowed to create policies
//
async function checkCreateDelegationEvidence(eori, access_token) {
    debug('Check at AR if sender is allowed to create policies');
    const payload = await getDelegationEvidence(eori);
    debug('Required delegationEvidence: %j', payload);
    const options = {
	method: "POST",
	body: JSON.stringify(payload),
	headers: {
	    "Content-Type": "application/json",
	    "Authorization": "Bearer " + access_token
	}
    };
	if(config.ar_delegation.toLowerCase().startsWith("https://")) {
		options.agent = httpsAgent;
	}
    let evidence = null;
    try {
	debug('Sending delegationRequest to AR');
	const ar_response = await fetch(config.ar_delegation, options);
	if (ar_response.status == 404) {
	    debug('Received 404 NotFound error');
	    return "Policy not found at AR, Creating policies not permitted";
	}
	if (ar_response.status != 200) {
	    const err_body = await ar_response.text();
	    debug('Wrong status code in response: %o', err_body);
	    return "Error when retrieving policy from AR: " + err_body;
	}
	const res_body = await ar_response.json();
	if ( !res_body.delegation_token) {
	    debug('No delegation_token found in response: %o', res_body);
	    return "Received invalid response from AR: " + JSON.stringify(res_body);
	}
	let decoded_delegation = jwt.decode(res_body.delegation_token);
	debug('Check for Permit rule in delegationEvidence: %j', decoded_delegation);
	if (decoded_delegation.delegationEvidence) {
	    let delev = decoded_delegation.delegationEvidence;
	    let psets = delev.policySets;
	    if (psets && psets.length > 0) {
		let pset = psets[0];
		if (pset && pset.policies && pset.policies.length > 0) {
		    let p = pset.policies[0];
		    if (p && p.target && p.target.resource && p.target.resource.type &&
			p.target.resource.type == "delegationEvidence") {
			if (p.rules && p.rules.length > 0) {
			    let r = p.rules[0];
			    if (r && r.effect && r.effect == "Permit") {
				return null;
			    }
			}
		    }
		}
	    }
	}
	return "Creating policies not permitted";
    } catch (e) {
	console.error(e);
	let msg = "General error when obtaining delegation evidence from AR";
	if (e.response) {
	    msg = msg += ": " + e.response.text();
	}
	return msg;
    }
    
    return "Checking for delegation evidence to create policies failed!";
}

// Create requested policy at AR
//
async function createPolicy(token, payload) {
    debug('Creating new policy at AR');
    let result = {
	policy_token: null,
	err: null
    };
    const options = {
	method: "POST",
	body: JSON.stringify(payload),
	headers: {
	    "Content-Type": "application/json",
	    "Authorization": "Bearer " + token,
	    "Accept": "application/json"
	}
    };
	if(config.ar_policy.toLowerCase().startsWith("https://")) {
		options.agent = httpsAgent;
	}
    try {
	debug('Sending request to AR /policy endpoint with policy: %j', payload);
	const ar_response = await fetch(config.ar_policy, options);
	if (ar_response.status != 200) {
	    const err_body = await ar_response.text();
	    result.err = "Error when creating policy at AR: " + err_body;
	    return result;
	}
	const res_body = await ar_response.json();
	if (!res_body.policy_token) {
	    debug('Received invalid response: %o', res_body);
	    result.err = "Received invalid response from AR when creating policy: " + JSON.stringify(res_body);
	    return result;
	}
	result.policy_token = res_body.policy_token;
	return result;
    } catch (e) {
	console.error(e);
	let msg = "General error when creating policy at AR";
	if (e.response) {
	    msg = msg += ": " + e.response.text();
	}
	debug(msg);
	result.err = msg;
	return result;
    } 
}

// Perform createPolicy request
//
async function performCreatePolicy(req, res, db, chain) {
    // Get Autorization header
    debug('Extracting authorization header');
    if ( !req.header('Authorization')) {
	debug("Missing Authorization header");
	error(400, "Missing Authorization header", res);
	return null;
    }
    const auth = req.header('Authorization');
    let token = null;
    if (auth.startsWith("Bearer ")){
	token = auth.split(" ")[1];
    } 
    if (!token) {
	debug('No authorization header found: %o', auth);
	error(400, "Missing Authorization header Bearer token", res);
	return null;
    }

    // Get DB entry for token
    debug('Retrieving token from DB');
    const db_token = await database.getByToken(token, db);
    if (!db_token.token) {
	let msg = "No valid token supplied";
	if (db_token.err) {
	    msg += ": " + db_token.err;
	}
	debug(msg);
	error(400, msg, res);
	return null;
    }
    
    // Get token from AR
    const access_token = await getToken(chain);

    // Check for policy at AR, if sender is allowed to create delegation evidence
    const err = await checkCreateDelegationEvidence(db_token.token.eori, access_token);
    if (err) {
	let msg = db_token.token.eori + " was not issued required policy: " + err;
	debug(msg);
	error(400, msg, res);
	return null;
    }

    // Create requested policy at AR
    const presult = await createPolicy(access_token, req.body);
    if (presult.err) {
	let msg = "Creating policy failed: " + presult.err;
	debug(msg);
	error(400, msg, res);
	return null;
    }

    return presult;
}

module.exports = {
    performCreatePolicy: performCreatePolicy
};
