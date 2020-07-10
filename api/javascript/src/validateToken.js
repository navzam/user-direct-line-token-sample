const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { promisify } = require('util');

// TODO: Ideally this jwks URI should come directly from the identity provider's OIDC metadata document
//       See docs about AAD's metadata endpoint: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#fetch-the-openid-connect-metadata-document
const jwkClient = jwksClient({
    jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
});

const getSigningKeyAsync = promisify(jwkClient.getSigningKey).bind(jwkClient);

module.exports = async function validateTokenAsync(token, validationOptions) {
    const decodedToken = jwt.decode(token, { complete: true });
    if (decodedToken === null || typeof decodedToken === 'string') {
        return null;
    }
    
    const tokenHeader = decodedToken['header'];
    if (tokenHeader.kid === undefined) {
        return null;
    }

    const keyResult = await getSigningKeyAsync(tokenHeader.kid);
    const pubKey = keyResult.getPublicKey();

    // Validate ID token
    try {
        return jwt.verify(token, pubKey, validationOptions);
    } catch (e) {
        if (e instanceof jwt.JsonWebTokenError
            || e instanceof jwt.NotBeforeError
            || e instanceof jwt.TokenExpiredError) {
            return null;
        }

        throw e;
    }
};