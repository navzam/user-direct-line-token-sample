const express = require('express');

const fetchDirectLineTokenAsync = require('./fetchDirectLineToken');
const validateTokenAsync = require('./validateToken');

// Verify required environment variables
const port = enforceEnvironmentVariable('PORT');
const directLineSecret = enforceEnvironmentVariable('DIRECT_LINE_SECRET');
const validTokenAudience = enforceEnvironmentVariable('VALID_TOKEN_AUDIENCE');
const validTokenIssuer = enforceEnvironmentVariable('VALID_TOKEN_ISSUER');

// Create Express application
const app = express();
app.use(express.json());

// Endpoint for generating a Direct Line token, given an ID token in the body
app.post('/api/direct-line-token', async (req, res) => {
    // Set CORS header. For simplicity, allow requests from all origins
    // You should restrict this to specific domains
    res.header('Access-Control-Allow-Origin', '*');

    // Extract ID token from body
    const idToken = req.body['id_token'];
    if (typeof idToken !== 'string') {
        res.status(400).send({ message: 'invalid format for id_token parameter' });
        return;
    }

    // Validate ID token
    const tokenClaims = await validateTokenAsync(idToken, { audience: validTokenAudience, issuer: validTokenIssuer });
    if (tokenClaims === null) {
        res.status(400).send({ message: 'invalid token' });
        return;
    }

    // Extract user ID from ID token
    const userId = getUserIdFromTokenClaims(tokenClaims);
    if (userId === null) {
        res.status(400).send({ message: 'token does not contain sub claim' });
        return;
    }

    // Get user-specific DirectLine token and return it
    let directLineTokenResponse;
    try {
        directLineTokenResponse = await fetchDirectLineTokenAsync(directLineSecret, userId);
    } catch (e) {
        if (e instanceof Error) {
            res.status(400).send({ message: e.message });
            return;
        }

        throw e;
    }

    const response = { ...directLineTokenResponse, userId: userId };
    res.send(response);
});

app.listen(port, () => {
    console.log(`API running on port ${port}`);
});

// Constructs a user ID from a set of token claims
// In this sample, we select the "sub" claim
// Prefixed with "dl_", as required by the Direct Line API
function getUserIdFromTokenClaims(tokenClaims) {
    const sub = tokenClaims['sub'];

    return (typeof sub === 'string' && sub.length > 0) ? `dl_${sub}` : null;
}

// Tries to return the value of an environment variable
// Quits if the variable doesn't exist
function enforceEnvironmentVariable(name) {
    const value = process.env[name];
    if (value === undefined || value.length === 0) {
        console.error(`Required environment variable not set: ${name}`);
        process.exit();
    }

    return value;
}