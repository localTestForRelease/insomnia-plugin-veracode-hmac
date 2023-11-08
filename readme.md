# insomnia-plugin-veracode-hmac

Adds an HMAC authentication header to Veracode API requests in Insomnia

## Install

Add `insomnia-plugin-veracode-hmac` to the plugins list in Preferences -> Plugins

## Setup

Veracode ID/KEY credentials must be saved in `~/.veracode/credentials`

```
[default]
veracode_api_key_id = 462a796c.....
veracode_api_key_secret = 2aa443c7.....

[someotheraccount]
veracode_api_key_id = 297d2576.....
veracode_api_key_secret = ba75d9ba.....
```

The authentication profile used can be selected using an environment variable in your Insomnia workspace

```
{
    "veracode_auth_profile": "someotheraccount"
}
```

## Insomnia workspace

An Insomnia workspace export is available in `veracode-rest-api.json`

somechange
somechange pull
