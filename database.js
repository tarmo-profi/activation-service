var sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const config = require('./config.js');

const DBSOURCE = config.db_source;

// Open DB
async function openDB() {
    console.log("Connecting to SQLite Database:", config.db_source);
    let db = await open({
	filename: config.db_source,
	driver: sqlite3.Database
    });

    try {
	console.log("Setup database...");  
	await db.run(`CREATE TABLE token (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            eori text NOT NULL UNIQUE, 
            access_token text NOT NULL UNIQUE, 
            expires int NOT NULL
            )`);
	console.log("Created new database");
    } catch (err) {
	console.log("Loaded existing database");
	let clean_err = await clean(db);
	if (clean_err) {
	    console.log("Error cleaning tokens: ", clean_err);
	    throw clean_err;
	}
    }
    return db;
}

async function insertToken(token, db) {
    var sql = 'INSERT OR REPLACE INTO token (eori, access_token, expires) VALUES (?,?,?)';
    var params = [ token.eori, token.access_token, token.expires];
    try {
	const result = await db.run(sql, params);
	return null;
    } catch (err) {
	console.error(err);
	return err;
    }
    
}

async function getByEORI(eori, db) {
    let result = {
	token: null,
	err: null
    };
    let clean_err = await clean(db);
    if (clean_err) {
	result.err = clean_err;
	return result;
    }
    var sql = 'SELECT eori, access_token, expires FROM token WHERE eori = ?';
    try {
	const res = await db.get(sql, eori);
	result.token = res;
    } catch (err) {
	result.err = err;
    }
    return result;
}

async function getByToken(token, db) {
    let result = {
	token: null,
	err: null
    };
    let clean_err = await clean(db);
    if (clean_err) {
	result.err = clean_err;
	return result;
    }
    var sql = 'SELECT eori, access_token, expires FROM token WHERE access_token = ?';
    try {
	const res = await db.get(sql, token);
	result.token = res;
    } catch (err) {
	result.err = err;
    }
    return result;
}

async function clean(db) {
    let cur_date = Date.now();
    try {
	const result = await db.run('DELETE FROM token WHERE expires < ?',
				    cur_date);
	return null;
    } catch (err) {
	console.error("err:",err);
	return err;
    }
}

module.exports = {
    openDB: openDB,
    clean: clean,
    insertToken: insertToken,
    getByEORI: getByEORI,
    getByToken: getByToken
};
