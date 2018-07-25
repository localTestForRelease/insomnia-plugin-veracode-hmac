const path = require('path');
const os = require('os');
const hmac = require('./veracode-hmac.js');
const ConfigParser = require('configparser');

// Request hook to set header on every request
module.exports.requestHooks = [
    context => {

        const authProfile = context.request.getEnvironmentVariable('veracode_auth_profile');
        if (!authProfile) {
            authProfile = 'default'
        }

        const veracodeCredsFile = path.join(os.homedir(), '.veracode', 'credentials');
        const config = new ConfigParser();
        config.read(veracodeCredsFile);
        const id = config.get(authProfile, 'veracode_api_key_id');
        const key = config.get(authProfile, 'veracode_api_key_secret'); 
        const hostname = "api.veracode.com";
        
    if (context.request.getUrl().startsWith('https://api.veracode.com')) {
        var parser = document.createElement('a');
        parser.href = context.request.getUrl();

        var header = hmac.CalculateAuthorizationHeader(id, key, hostname, parser.pathname, parser.search, context.request.getMethod());
        context.request.setHeader('Authorization', header);
    }
}];