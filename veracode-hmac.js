const sjcl = require('sjcl');
const util = require('util');
const crypto = require('crypto');

exports.CalculateAuthorizationHeader = calculateAuthorizationHeader;

function getAuthorizationScheme() { return "VERACODE-HMAC-SHA-256"; }
function getRequestVersion() { return "vcode_request_version_1"; }
function getNonceSize() { return 16; }

function computeHash(message, key) {
    var key_bits = sjcl.codec.utf8String.toBits(key);
    var hmac_bits = (new sjcl.misc.hmac(key_bits, sjcl.hash.sha256)).mac(message);
    var hmac = sjcl.codec.hex.fromBits(hmac_bits)
    return hmac;
}

function computeHashHex(message, key_hex) {
    var key_bits = sjcl.codec.hex.toBits(key_hex);
    var hmac_bits = (new sjcl.misc.hmac(key_bits, sjcl.hash.sha256)).mac(message);
    var hmac = sjcl.codec.hex.fromBits(hmac_bits);
    return hmac;
}

function calulateDataSignature(apiKeyBytes, nonceBytes, dateStamp, data) {
    var kNonce = computeHashHex(nonceBytes, apiKeyBytes);
    var kDate = computeHashHex(dateStamp, kNonce);
    var kSig = computeHashHex(getRequestVersion(), kDate);
    var kFinal = computeHashHex(data, kSig);
    return kFinal;
}

function newNonce() {
    return crypto.randomBytes(getNonceSize()).toString('hex').toUpperCase();
}

function toHexBinary(input) {
    return sjcl.codec.hex.fromBits(sjcl.codec.utf8String.toBits(input));
}

function calculateAuthorizationHeader(id, key, hostName, uriString, urlQueryParams, httpMethod) {
    uriString += urlQueryParams;
    var data = util.format("id=%s&host=%s&url=%s&method=%s", id, hostName, uriString, httpMethod);
    var dateStamp = Date.now().toString();
    var nonceBytes = newNonce(getNonceSize());
    var dataSignature = calulateDataSignature(key, nonceBytes, dateStamp, data);
    var authorizationParam = util.format("id=%s,ts=%s,nonce=%s,sig=%s", id, dateStamp, toHexBinary(nonceBytes), dataSignature.toUpperCase());
    var header = getAuthorizationScheme() + " " + authorizationParam;
    return header;
}