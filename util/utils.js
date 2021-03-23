

// Return error response
//
function error(code, msg, res) {
    res.status(code).send({
	status: "ERROR",
	msg: msg
    });
}

module.exports = {
    error: error
};
