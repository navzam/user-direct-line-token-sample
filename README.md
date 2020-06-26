# User-specific Direct Line token sample

This sample demonstrates how to implement WebChat in a way that ensures your bot will receive a consistent and trustworthy user ID across sessions. Specifically, it shows how to retrieve a user-specific Direct Line token for a user who has been verified by an identity provider.

## Motivation

When embedding WebChat into a site, you must provide either your Direct Line secret or a Direct Line token so that WebChat can communicate with bot. Using the Direct Line secret directly is strongly discouraged because it would expose your secret on the client-side. Instead, the recommended approach is to exchange the secret for a Direct Line token on the server-side.

Still, a simple secret-to-token exchange has one major issue: There is no guarantee of the user's identity. While you can set a `userId` when initializing WebChat, this `userId` is not tamper-proof. A malicious user can easily modify the `userId` and initialize WebChat under an ID of their choice, including another user's ID. Therefore, your bot cannot trust the incoming `userId`.

To prevent impersonation, you could generate random unguessable user IDs, but then your bot would not receive a consistent user ID across sessions. 

This sample solves the problem by verifying a user's identity and binding their user ID to the Direct Line token during token acquisition. This prevents impersonation because a malicious user will not be able to prove that they are someone else. It also guarantees a consistent user ID since it leverages an existing consistent identity.

## Architecture

This sample contains a backend API that performs the Direct Line token acquisition. It expects an OpenID Connect (OIDC) JWT (called an ID token) that identifies the user. The API goes through the following steps:

1. Validate the ID token against the chosen identity provider (AAD in this sample).
1. Build a user ID using the validated token's claims. We chose to use the `sub` (subject) claim because it's a standard OIDC claim that uniquely identifies the user, and it doesn't require any additional scopes.
    - In AAD, the `sub` claim is only consistent per user *per application*. This means our user ID wouldn't be sufficient for looking up the user in other systems (such as Microsoft Graph). If we needed a user ID that identifies the user across applications, we could use the `oid` (object ID) claim, but it requires the `profile` scope. See [AAD ID token claims](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#claims-in-an-id_token) for more details.
    - Since the user identity is verified, it is okay for this user ID to be a "guessable" value.
1. Retrieve a user-specific Direct Line token using the Direct Line API.
1. Respond with the user-specific Direct Line token.

Depending on the scenario, the backend API could be called from a client (such as a single-page application) or a server (such as a more traditional web app, where tokens are handled server-side). The only requirement is that the caller can provide an ID token from the expected identity provider. If you are embedding the bot in an authenticated site, then you may already have an ID token that you can use.

After receiving the Direct Line token, the caller can then use it to render Web Chat, and the bot will receive a consistent user ID that it can rely on.

## Code highlights

### Receiving the ID token

The API expects the ID token to be passed in the request body:

```ts
// server.ts

const idToken = req.body['id_token'];
```

Tokens are typically sent as bearer tokens in the `Authorization` header. However, we aren't using the user's ID token to protect the API. Rather, it is a parameter of the request itself. Although the API isn't protected in this sample, you could protect the API using a different token (such as an OAuth access token) which *would* go in the `Authorization` header.

### Validating the ID token

We use two libraries to achieve token validation: [jwks-rsa](https://www.npmjs.com/package/jwks-rsa) and [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken). We first use `jwks-rsa` to retrieve the AAD public keys used to sign the token:

```ts
// tokenValidation.ts

const decodedToken = jwt.decode(token, { complete: true });
...
const tokenHeader: JwtHeader = decodedToken['header'];
...
const keyResult = await getSigningKeyAsync(tokenHeader.kid); // from jwks-rsa
const pubKey = keyResult.getPublicKey();
```

and then use `jsonwebtoken` to validate the token:

```ts
// tokenValidation.ts

return jwt.verify(token, pubKey, validationOptions) as Record<string, any>;
```

`validationOptions` define certain parameters of the validation, such as the expected audience and issuer.

### Constructing the user ID

In this sample, we directly use the `sub` claim of the token as the user ID:

```ts
// server.ts

function getUserIdFromTokenClaims(tokenClaims: Record<string, any>) {
    const sub = tokenClaims['sub'];

    return (typeof sub === 'string' && sub.length > 0) ? sub : null;
}
```

You could customize this to use different claims depending on your needs. See [Architecture](#Architecture) for an explanation of why we chose the `sub` claim.

### Retrieving a user-specific Direct Line token

We call the Direct Line API to retrieve a Direct Line token. Notice that we pass the user ID in the body of the request:

```ts
const response = await fetch('https://directline.botframework.com/v3/directline/tokens/generate', {
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${secret}`,
        },
        method: 'post',
        body: JSON.stringify({ user: { id: userId } })
    });
```

## Running the sample

1. Fill in the environment variables in the `.env` file, according to the following table:
    | Variable | Description | Example value |
    | -------- | ----------- | ------------- |
    | `PORT` | The port on which the API server will run. | 3000 |
    | `DIRECT_LINE_SECRET` | The Direct Line secret issued by Bot Framework. Can be found in the Azure Bot Channels Registration resource after enabling the Direct Line channel. |  |
    | `VALID_TOKEN_AUDIENCE` | The expected audience of the ID token. If using AAD, this should be the client ID of the app registration for the web app. | 34d690a0-a2fb-4163-9dde-404105d88c30 |
    | `VALID_TOKEN_ISSUER` | The expected issuer of the ID token. If using AAD, this should include the tenant ID that users will be coming from. See the example value for the format | https://login.microsoftonline.com/58e260b0-56cc-4764-8cfc-cd9090194413/v2.0 |
1. Run `npm install` to install the required dependencies.
1. Run `npm build` and then `npm start` to start the server.

## Notes
- Although this sample uses AAD, you can achieve the same result using a different identity provider.
