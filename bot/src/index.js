const restify = require('restify');
const { BotFrameworkAdapter } = require('botbuilder');

const appId = enforceEnvironmentVariable('MICROSOFT_APP_ID');
const appPassword = enforceEnvironmentVariable('MICROSOFT_APP_SECRET');
const port = enforceEnvironmentVariable('PORT');

// Create adapter
const adapter = new BotFrameworkAdapter({ appId, appPassword });

// Create HTTP server
const server = restify.createServer();

server.post('/api/messages', (req, res) => {
    adapter.processActivity(req, res, async (context) => {
        // Respond to all activities by sending the user's ID
        await context.sendActivity(`Your user ID is ${context.activity.from.id}`);
    });
});

server.listen(port, () => {
    console.log(`${server.name} listening to ${server.url}`);
});

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