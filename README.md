# User-specific Direct Line token sample

This sample demonstrates how to implement WebChat in a way that (a) does not expose your Direct Line secret to the browser, and (b) ensures your bot will receive a consistent and trustworthy user ID across sessions. Specifically, it shows how to retrieve a user-specific Direct Line token for a user who has been verified by an identity provider.

## Motivation

In the [Direct Line token sample](https://github.com/navzam/direct-line-token-sample), in order to hide the WebChat secret and avoid user impersonation, we bound a random user ID to the Direct Line token. The downside of that approach is that users will have a different ID every time they talk to the bot. We could improve on this by storing a user ID in client-side storage (cookie, `localStorage`, etc.) and sending it to the token API, but there would still be two issues:
- The user ID would be tied to the browser and wouldn't be consistent across browsers, devices, etc.
- A malicious user could modify their user ID to attempt to impersonate a different user, so the bot wouldn't be able to trust the user ID.

A better approach is to leverage a user's existing identity from a true identity provider. The user must first sign in to the site before talking to the bot. Then, if the user signs in using the same identity on a different browser or device, the user ID will be the same. This also prevents user impersonation because we can verify the user's identity with the identity provider instead of blindly trusting the user ID.

## Architecture

This sample contains three components:
- **The backend API** performs the Direct Line token acquisition. It verifies the user's identity and then acquires a Direct Line token that is bound to that identity.
- **The UI** is static HTML/JS that could be hosted using any web server. It requires the user to sign in, then makes a request to the backend API with proof of the user's identity. It uses the resulting Direct Line token to render WebChat.
- **The bot** is a bare-bones bot that responds to every activity by sending the user's ID.  

The interesting component is the backend API, which goes through the following steps:

1. In the body of the POST request to the API, receive an OpenID Connect (OIDC) JWT (called an ID token) that identifies the user.
1. Validate the ID token against the chosen identity provider (AAD in this sample).
1. Build a user ID using claims from the validated token. We chose to use the `sub` (subject) claim because it's a standard OIDC claim that uniquely identifies the user, and it doesn't require any additional scopes.
    - In AAD, the `sub` claim is only consistent per user *per application*. This means our user ID wouldn't be sufficient for looking up the user in other systems (such as Microsoft Graph). If we needed a user ID that identifies the user across applications, we could use the `oid` (object ID) claim, but it requires the `profile` scope. See [AAD ID token claims](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#claims-in-an-id_token) for more details.
    - Since the user identity is verified, it is okay for this user ID to be a "guessable" value.
1. Retrieve a user-specific Direct Line token using the Direct Line API.
1. Respond with the user-specific Direct Line token.

Depending on the scenario, the backend API could be called from a client (such as a single-page application) or a server (such as a more traditional web app, where tokens are handled server-side). The only requirement is that the caller can provide an ID token from the expected identity provider. If you are embedding the bot in an authenticated site, then you may already have an ID token that you can use.

After receiving the Direct Line token, the caller can then use it to render Web Chat, and the bot will receive a consistent user ID that it can rely on.

## Code highlights

### Receiving the ID token

The API expects the ID token to be passed in the request body:

<details><summary>JavaScript</summary>

```js
// server.js

const idToken = req.body['id_token'];
```

</details>

<details><summary>C#</summary>

```csharp
// DirectLineTokenController.cs

public class TokenRequest
{
    [JsonPropertyName("id_token")]
    public string idToken { get; set; }
}
...
public async Task<IActionResult> Post([FromBody] TokenRequest request)
{
    ...
}
```

</details>

Tokens are typically sent as bearer tokens in the `Authorization` header. However, we aren't using the user's ID token to protect the API. Rather, it is a parameter of the request itself. Although the API isn't protected in this sample, you could protect the API using a different token (such as an OAuth access token) which *would* go in the `Authorization` header.

### Validating the ID token

<details><summary>JavaScript</summary>

We use two libraries to achieve token validation: [jwks-rsa](https://www.npmjs.com/package/jwks-rsa) and [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken). We first use `jwks-rsa` to retrieve the AAD public keys used to sign the token:

```js
// validateToken.js

const decodedToken = jwt.decode(token, { complete: true });
...
const tokenHeader = decodedToken['header'];
...
const keyResult = await getSigningKeyAsync(tokenHeader.kid);
const pubKey = keyResult.getPublicKey();
```

and then use `jsonwebtoken` to validate the token:

```js
// validateToken.js

return jwt.verify(token, pubKey, validationOptions);
```

`validationOptions` define certain parameters of the validation, such as the expected audience.

</details>

<details><summary>C#</summary>

We use two packages to achieve token validation: [Microsoft.IdentityModel.Protocols.OpenIdConnect](https://www.nuget.org/packages/Microsoft.IdentityModel.Protocols.OpenIdConnect/) and [System.IdentityModel.Tokens.Jwt](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/). We first retrieve the AAD public keys used to sign the token:

```csharp
// DirectLineTokenController.cs

var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
    "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    new OpenIdConnectConfigurationRetriever(),
    new HttpDocumentRetriever());
...
var discoveryDocument = await configurationManager.GetConfigurationAsync(ct);
var signingKeys = discoveryDocument.SigningKeys;
```

and then validate the token:

```csharp
// DirectLineTokenController.cs

var principal = new JwtSecurityTokenHandler()
    .ValidateToken(token, validationParameters, out var rawValidatedToken);
```

`validationParameters` define certain parameters of the validation, such as the expected audience.

</details>

### Constructing the user ID

In this sample, we directly use the `sub` claim of the token as the user ID:

<details><summary>JavaScript</summary>

```js
// server.js

function getUserIdFromTokenClaims(tokenClaims) {
    const sub = tokenClaims['sub'];

    return (typeof sub === 'string' && sub.length > 0) ? `dl_${sub}` : null;
}
```

</details>

<details><summary>C#</summary>

```csharp
// DirectLineTokenController.cs

private static string GetUserIdFromTokenClaims(JwtSecurityToken token)
{
    ...
    var subject = token.Subject;
    return String.IsNullOrEmpty(subject) ? null : $"dl_{subject}";
}
```

</details>

You could customize this to use different claims depending on your needs. See [Architecture](#Architecture) for an explanation of why we chose the `sub` claim.

### Retrieving a user-specific Direct Line token

The API calls the Direct Line API to retrieve a Direct Line token. Notice that we pass the user ID in the body of the request:

<details><summary>JavaScript</summary>

```js
// fetchDirectLineToken.js

const response = await fetch('https://directline.botframework.com/v3/directline/tokens/generate', {
    headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${secret}`,
    },
    method: 'post',
    body: JSON.stringify({ user: { id: userId } })
});
```

</details>

<details><summary>C#</summary>

```csharp
// DirectLineTokenService.cs

httpClient.BaseAddress = new Uri("https://directline.botframework.com/");
...
var fetchTokenRequestBody = new { user = new { id = userId } };

var fetchTokenRequest = new HttpRequestMessage(HttpMethod.Post, "v3/directline/tokens/generate")
{
    Headers =
    {
        { "Authorization", $"Bearer {directLineSecret}" },
    },
    Content = new StringContent(JsonSerializer.Serialize(fetchTokenRequestBody), Encoding.UTF8, MediaTypeNames.Application.Json),
};

var fetchTokenResponse = await _httpClient.SendAsync(fetchTokenRequest, cancellationToken);
```

</details>

The resulting Direct Line token will be bound to the passed user ID.

### Calling the API and rendering WebChat

After the user signs in, the UI calls the API with the user's ID token and uses the resulting Direct Line token to render WebChat:

```js
// index.html

async function getDirectLineToken(idToken) {
    const res = await fetch('http://localhost:3000/api/direct-line-token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ id_token: idToken }),
    });
    ...
    return await res.json();
}
...
const directLineTokenResponse = await getDirectLineToken(idToken);
...
WebChat.renderWebChat(
    {
        directLine: WebChat.createDirectLine({ token: directLineTokenResponse.token }),
    },
    document.getElementById('webchat')
);
```

Note that we do *not* specify a user ID when initiating WebChat. Direct Line will handle sending the user ID to the bot based on the token.

## Running the sample locally

### Prerequisites
- A registered Bot Framework bot (see [documentation on registering a bot with Azure Bot Service](https://docs.microsoft.com/en-us/azure/bot-service/bot-service-quickstart-registration?view=azure-bot-service-3.0))

### Register an AAD application
Since the user will be signing in to the web app using AAD, we must register an AAD application. See the [docs for registering an AAD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) or follow these steps:
1. Sign in to the [Azure portal](https://portal.azure.com/) and find the **Azure Active Directory** section.
1. In **App registrations**, click **New registration** and fill in the following details:
    - **Name**: A meaningful display name, like "Direct Line Token Sample"
    - **Supported account types**: 	Accounts in any organizational directory (Any Azure AD directory - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)
    - **Redirect URI**: Select **Web** and enter `http://localhost:5500`
1. Click **Register**.
1. In the **Overview** blade, copy the **Application (client) ID**. We will use this later.
1. In the **Authentication** blade, under **Implicit grant**, check the box for **ID tokens** and click **Save**.


### Run the bot
1. Navigate to the `bot` directory.
1. Fill in the environment variables in the `.env` file, according to the following table:
    | Variable | Description | Example value |
    | -------- | ----------- | ------------- |
    | `PORT` | The port on which the bot server will run. | 3978 |
    | `MICROSOFT_APP_ID` | The app ID of the registered Bot Framework bot. Can be found in the Azure Bot Channels Registration resource. | |
    | `MICROSOFT_APP_SECRET` | The app secret of the registered Bot Framework Bot. Issued during registration. | |
1. Run `npm install` to install the required dependencies.
1. Run `npm start` to start the bot.
1. Run `ngrok` to expose your bot to a public URL. For example:
    ```bash
    ngrok http -host-header=rewrite 3978
    ```
1. Update the messaging endpoint in your Bot Channels Registration to the ngrok URL. For example: `https://abcdef.ngrok.io/api/messages`

### Run the API

The sample API is available in multiple languages. Choose one and expand the corresponding section for specific steps.

<details><summary>JavaScript API</summary>

1. Navigate to the `api/javascript` directory.
1. Fill in the environment variables in the `.env` file. See the table below for descriptions.
1. Run `npm install` to install the required dependencies.
1. Run `npm start` to start the server.

| Variable | Description | Example value |
| -------- | ----------- | ------------- |
| `PORT` | The port on which the API server will run. | 3000 |
| `DIRECT_LINE_SECRET` | The Direct Line secret issued by Bot Framework. Can be found in the Azure Bot Channels Registration resource after enabling the Direct Line channel. |  |
| `VALID_TOKEN_AUDIENCE` | The expected audience of the ID token. When using AAD, this should be the client ID of the app registration created above. | 34d690a0-a2fb-4163-9dde-404105d88c30 |

</details>

<details><summary>C# API</summary>

1. Add the required secrets to the .NET Core secret manager. See the table below for descriptions.
    ```bash
    cd ./api/csharp
    dotnet user-secrets set "DirectLine:DirectLineSecret" "YOUR-DIRECT-LINE-SECRET-HERE"
    ```
1. Fill in the environment variables in the `appsettings.json` file. See the table below for descriptions.
1. (optional) Change the port specified in `./Properties/launchSettings.json`.
1. Run `dotnet run` to start the server. (Alternatively, open and run the project in Visual Studio.)

| Variable | Description | Example value |
| -------- | ----------- | ------------- |
| `DirectLine:DirectLineSecret` | The Direct Line secret issued by Bot Framework. Can be found in the Azure Bot Channels Registration resource after enabling the Direct Line channel. |  |
| `TokenValidationSettings:ValidAudience` | The expected audience of the ID token. When using AAD, this should be the client ID of the AAD app created above. | 34d690a0-a2fb-4163-9dde-404105d88c30 |

</details>

### Run the UI
1. Navigate to the `ui` directory.
1. Open `index.html` in an editor, find the empty variables at the top of the `script` tag, and fill in the values according to the following table:

    | Variable | Description | Example value |
    | -------- | ----------- | ------------- |
    | `AAD_APP_ID` | The client ID of the AAD app created above. | 34d690a0-a2fb-4163-9dde-404105d88c30 |
    | `AAD_REDIRECT_URI` | The redirect URI registered in the AAD app created above. | http://localhost:5500 |

1. Serve `index.html` on `localhost:5500` using a web server.
    - A quick way to get started is using the [http-server](https://www.npmjs.com/package/http-server) npm package. You can use `npx` to run it without installation:
        ```bash
        npx http-server ./ -p 5500
        ```
    - Another option is a local development server such as the [Live Server Visual Studio Code extension](https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer).
1. Open `http://localhost:5500` in a browser and sign in.

## Notes
- Although this sample uses AAD, you can achieve the same result using a different identity provider.
