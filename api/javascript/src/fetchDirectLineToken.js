const fetch = require('node-fetch');

module.exports = async function fetchDirectLineTokenAsync(secret, userId) {
    const response = await fetch('https://directline.botframework.com/v3/directline/tokens/generate', {
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${secret}`,
        },
        method: 'post',
        body: JSON.stringify({ user: { id: userId } })
    });

    if (!response.ok) {
        throw new Error(`Direct Line token API call failed with status ${response.status}`);
    }

    const tokenResponse = await response.json();

    return tokenResponse;
};

// export interface DirectLineTokenResponse {
//     token: string,
//     expires_in: number,
//     conversationId: string,
// }