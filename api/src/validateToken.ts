import jwt, { VerifyOptions, JwtHeader } from "jsonwebtoken";
import jwksClient from 'jwks-rsa';
import { promisify } from 'util';

// TODO: Ideally this jwks URI should come directly from the identity provider's OIDC metadata document
//       See docs about AAD's metadata endpoint: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#fetch-the-openid-connect-metadata-document
const jwkClient = jwksClient({
    jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
});

const getSigningKeyAsync = promisify(jwkClient.getSigningKey).bind(jwkClient);

export async function validateTokenAsync(token: string, validationOptions: VerifyOptions) {
    const decodedToken = jwt.decode(token, { complete: true });
    if (decodedToken === null || typeof decodedToken === 'string') {
        return null;
    }
    
    const tokenHeader: JwtHeader = decodedToken['header'];
    if (tokenHeader.kid === undefined) {
        return null;
    }

    const keyResult = await getSigningKeyAsync(tokenHeader.kid);
    const pubKey = keyResult.getPublicKey();

    // Validate ID token
    try {
        return jwt.verify(token, pubKey, validationOptions) as Record<string, any>;
    } catch (e) {
        if (e instanceof jwt.JsonWebTokenError
            || e instanceof jwt.NotBeforeError
            || e instanceof jwt.TokenExpiredError) {
            return null;
        }

        throw e;
    }    
}