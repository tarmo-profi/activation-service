const config = require('./config.js');
var database = require('./database.js');
const moment = require('moment');
const uuid = require('uuid');
const fetch = require('node-fetch');
const https = require('https');
const jose = require('node-jose');
var jwt = require('jsonwebtoken');
var bodyParser = require('body-parser');
const express = require('express');
const app = express();

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

// Return error response
//
function error(code, msg, res) {
    res.status(code).send({
	status: "ERROR",
	msg: msg
    });
}

// Forward token request to AR
//
async function forward_token(req, res) {
    if ( !req.body.client_id) {
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
	    agent: httpsAgent
	}
	const ar_response = await fetch(config.ar_token, options);
	const res_body = await ar_response.json();
	if (ar_response.status != 200) {
	    res.status(ar_response.status).send(res_body);
	    return null;
	}
	if ( !res_body.access_token || !res_body.expires_in) {
	    error(400, "Received invalid response from AR: " + JSON.stringify(res_body), res);
	    return null;
	}
	token = {
	    eori: eori,
	    access_token: res_body.access_token,
	    expires: Date.now() + (1000*res_body.expires_in)
	};
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

// Creates JWT for obtaining token at AR
//
async function createJwt() {
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

// Get token from AR
//
async function getToken() {
    const jwtoken = await createJwt();
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
	    agent: httpsAgent
	}
	const ar_response = await fetch(config.ar_token, options);
	const res_body = await ar_response.json();
	if (ar_response.status != 200) {
	    return JSON.stringify(res_body);
	}
	if ( !res_body.access_token) {
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

async function checkCreateDelegationEvidence(eori, access_token) {

    // Check for delegation evidence to create policies
    const payload = await getDelegationEvidence(eori);
    const options = {
	method: "POST",
	body: JSON.stringify(payload),
	headers: {
	    "Content-Type": "application/json",
	    "Authorization": "Bearer " + access_token
	},
	agent: httpsAgent
    };
    let evidence = null;
    try {
	const ar_response = await fetch(config.ar_delegation, options);
	if (ar_response.status == 404) {
	    return "Policy not found at AR, Creating policies not permitted";
	}
	if (ar_response.status != 200) {
	    const err_body = await ar_response.text();
	    return "Error when retrieving policy from AR: " + err_body;
	}
	const res_body = await ar_response.json();
	if ( !res_body.delegation_token) {
	    return "Received invalid response from AR: " + JSON.stringify(res_body);
	}
	let decoded_delegation = jwt.decode(res_body.delegation_token);
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
	},
	agent: httpsAgent
    };
    try {
	const ar_response = await fetch(config.ar_policy, options);
	if (ar_response.status != 200) {
	    const err_body = await ar_response.text();
	    result.err = "Error when creating policy at AR: " + err_body;
	    return result;
	}
	const res_body = await ar_response.json();
	if (!res_body.policy_token) {
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
	result.err = msg;
	return result;
    } 
}

// /token
// Proxy request to /token endpoint of AR
// and store returned token
app.post('/token', async (req, res) => {
    const token = await forward_token(req, res);
    if ( !token ) {
	return;
    }
    
    // DB entry insert
    const ins_err = await database.insertToken(token.token, db);
    if (ins_err) {
	error(500, "Could not insert token into DB: " + ins_err, res);
	return;
    }
    
    // Return AR response
    res.send(token.response);
});

// /createpolicy
// Create policy at AR
app.post('/createpolicy', async (req, res) => {
    // Get Autorization header
    const auth = req.header('Authorization');
    let token = null;
    if (auth.startsWith("Bearer ")){
	token = auth.split(" ")[1];
    } 
    if (!token) {
	error(400, "Missing Authorization header Bearer token", res);
	return;
    }

    // Get DB entry for token
    const db_token = await database.getByToken(token, db);
    if (!db_token.token) {
	let msg = "No valid token supplied";
	if (db_token.err) {
	    msg += ": " + db_token.err;
	}
	error(400, msg, res);
	return;
    }
    
    // Get token from AR
    const access_token = await getToken();

    // Check for policy at AR to create delegation evidence
    const err = await checkCreateDelegationEvidence(db_token.token.eori, access_token);
    if (err) {
	let msg = db_token.token.eori + " was not issued required policy: " + err;
	error(400, msg, res);
	return;
    }

    // Create requested policy at AR
    const presult = await createPolicy(access_token, req.body);
    if (presult.err) {
	let msg = "Creating policy failed: " + presult.err;
	error(400, msg, res);
	return;
    }
    
    res.send({
	policy_token: presult.policy_token
    });
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
