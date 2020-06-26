import express from 'express';
import { fetchDirectLineTokenAsync, DirectLineTokenResponse } from './fetchDirectLineToken';
import { validateTokenAsync } from './validateToken';

// Verify required environment variables
const port = enforceEnvironmentVariable('PORT');
const directLineSecret = enforceEnvironmentVariable('DIRECT_LINE_SECRET');
const validTokenAudience = enforceEnvironmentVariable('VALID_TOKEN_AUDIENCE');
const validTokenIssuer = enforceEnvironmentVariable('VALID_TOKEN_ISSUER');

const app = express();
app.use(express.json());

// Endpoint for generating a Direct Line token, given an ID token in the body
app.post('/api/direct-line-token', async (req, res) => {
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
    let directLineResponse: DirectLineTokenResponse;
    try {
        directLineResponse = await fetchDirectLineTokenAsync(directLineSecret, userId);
    } catch (e) {
        if (e instanceof Error) {
            res.status(400).send({ message: e.message });
            return;
        }

        throw e;
    }

    res.send(directLineResponse);
});

app.listen(port, () => {
    console.log(`API running on port ${port}`);
});

// Constructs a user ID from a set of token claims
// In this sample, we select the "sub" claim
function getUserIdFromTokenClaims(tokenClaims: Record<string, any>) {
    const sub = tokenClaims['sub'];

    return (typeof sub === 'string' && sub.length > 0) ? sub : null;
}

// Tries to return the value of an environment variable
// Quits if the variable doesn't exist
function enforceEnvironmentVariable(name: string) {
    const value = process.env[name];
    if (value === undefined || value.length === 0) {
        console.error(`Required environment variable not set: ${name}`);
        process.exit();
    }

    return value;
}