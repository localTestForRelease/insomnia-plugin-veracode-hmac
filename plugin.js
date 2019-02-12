const path = require('path');
const os = require('os');
const configparser = require('configparser');
const hmac = require('./veracode-hmac.js');

const hosts = ['api.veracode.com', 'analysiscenter.veracode.com', 'api.veracode.io'];

// Request hook to set header on every request
module.exports.requestHooks = [
    context => {
        let url = new URL(context.request.getUrl());
        let params = context.request.getParameters();
        
        if (url.protocol === 'https:' && hosts.includes(url.hostname)) {
            let authProfile = context.request.getEnvironmentVariable('veracode_auth_profile');
            if (!authProfile) {
                authProfile = 'default';
            }
            let veracodeCredsFile = path.join(os.homedir(), '.veracode', 'credentials');
            let config = new configparser();
            config.read(veracodeCredsFile);
            let id = config.get(authProfile, 'veracode_api_key_id');
            let key = config.get(authProfile, 'veracode_api_key_secret'); 

            let paramStringInitialValue = url.search === '' ? '?' : url.search + '&';
            let paramsString = params.reduce((accum, item, index, arr) => {
                return accum + `${item.name}=${item.value}&`;
            }, paramStringInitialValue);
            paramsString = paramsString.slice(0, -1);

            let header = hmac.calculateAuthorizationHeader(id, key, url.hostname, url.pathname, paramsString, context.request.getMethod());
            context.request.setHeader('Authorization', header);
        }

    }
];