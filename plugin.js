const path = require('path');
const os = require('os');
const configparser = require('configparser');
const hmac = require('./veracode-hmac.js');

// Request hook to set header on every request
module.exports.requestHooks = [
    context => {
        let url = new URL(context.request.getUrl());
        
        if (url.protocol === 'https:' && url.hostname === 'api.veracode.com') {
            let authProfile = context.request.getEnvironmentVariable('veracode_auth_profile');
            if (!authProfile) {
                authProfile = 'default';
            }
            let veracodeCredsFile = path.join(os.homedir(), '.veracode', 'credentials');
            let config = new configparser();
            config.read(veracodeCredsFile);
            let id = config.get(authProfile, 'veracode_api_key_id');
            let key = config.get(authProfile, 'veracode_api_key_secret'); 

            let header = hmac.calculateAuthorizationHeader(id, key, url.hostname, url.pathname, url.search, context.request.getMethod());
            context.request.setHeader('Authorization', header);
        }

    }
];