// Platzhalter für die Midea-Gerätekommunikation
// Hier muss die Protokoll-Logik aus Python nach JS portiert werden

const crypto = require('crypto');
const net = require('net');

const MSGTYPE_HANDSHAKE_REQUEST = 0x0;
const MSGTYPE_HANDSHAKE_RESPONSE = 0x1;
const MSGTYPE_ENCRYPTED_RESPONSE = 0x3;
const MSGTYPE_ENCRYPTED_REQUEST = 0x6;

const crc8_854_table = [
    0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83,
    0xC2, 0x9C, 0x7E, 0x20, 0xA3, 0xFD, 0x1F, 0x41,
    0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E,
    0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC,
    0x23, 0x7D, 0x9F, 0xC1, 0x42, 0x1C, 0xFE, 0xA0,
    0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62,
    0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D,
    0x7C, 0x22, 0xC0, 0x9E, 0x1D, 0x43, 0xA1, 0xFF,
    0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5,
    0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07,
    0xDB, 0x85, 0x67, 0x39, 0xBA, 0xE4, 0x06, 0x58,
    0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A,
    0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6,
    0xA7, 0xF9, 0x1B, 0x45, 0xC6, 0x98, 0x7A, 0x24,
    0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B,
    0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9,
    0x8C, 0xD2, 0x30, 0x6E, 0xED, 0xB3, 0x51, 0x0F,
    0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD,
    0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92,
    0xD3, 0x8D, 0x6F, 0x31, 0xB2, 0xEC, 0x0E, 0x50,
    0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C,
    0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE,
    0x32, 0x6C, 0x8E, 0xD0, 0x53, 0x0D, 0xEF, 0xB1,
    0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73,
    0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49,
    0x08, 0x56, 0xB4, 0xEA, 0x69, 0x37, 0xD5, 0x8B,
    0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4,
    0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16,
    0xE9, 0xB7, 0x55, 0x0B, 0x88, 0xD6, 0x34, 0x6A,
    0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8,
    0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7,
    0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35
];

function crc8(data) {
    let crc_value = 0;
    for (const m of data) {
        let k = crc_value ^ m;
        if (k > 256) k -= 256;
        if (k < 0) k += 256;
        crc_value = crc8_854_table[k];
    }
    return crc_value;
}

class LocalSecurity {
    constructor() {
        this.blockSize = 16;
        this.iv = Buffer.alloc(16, 0);
        this.aes_key = Buffer.from('6a1a350e7a3d2d5e8b7c9f1e2b3c4d5f', 'hex');
        this.salt = Buffer.from('b5e8c2d3a1f4e6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1', 'hex');
        this._tcp_key = null;
        this._request_count = 0;
        this._response_count = 0;
    }
    aes_decrypt(raw) {
        try {
            const decipher = crypto.createDecipheriv('aes-128-ecb', this.aes_key, null);
            decipher.setAutoPadding(false);
            let decrypted = Buffer.concat([decipher.update(raw), decipher.final()]);
            // Remove PKCS7 padding
            const pad = decrypted[decrypted.length - 1];
            return decrypted.slice(0, decrypted.length - pad);
        } catch (e) {
            return Buffer.alloc(0);
        }
    }
    aes_encrypt(raw) {
        const cipher = crypto.createCipheriv('aes-128-ecb', this.aes_key, null);
        cipher.setAutoPadding(true);
        return Buffer.concat([cipher.update(raw), cipher.final()]);
    }
    aes_cbc_decrypt(raw, key) {
        const decipher = crypto.createDecipheriv('aes-128-cbc', key, this.iv);
        decipher.setAutoPadding(false);
        let decrypted = Buffer.concat([decipher.update(raw), decipher.final()]);
        return decrypted;
    }
    aes_cbc_encrypt(raw, key) {
        const cipher = crypto.createCipheriv('aes-128-cbc', key, this.iv);
        cipher.setAutoPadding(true);
        return Buffer.concat([cipher.update(raw), cipher.final()]);
    }
    encode32_data(raw) {
        return crypto.createHash('md5').update(Buffer.concat([raw, this.salt])).digest();
    }
    tcp_key(response, key) {
        if (response.equals(Buffer.from('ERROR'))) throw new Error('authentication failed');
        if (response.length !== 64) throw new Error('unexpected data length');
        const payload = response.slice(0, 32);
        const sign = response.slice(32);
        const plain = this.aes_cbc_decrypt(payload, key);
        if (!crypto.createHash('sha256').update(plain).digest().equals(sign)) throw new Error('sign does not match');
        this._tcp_key = Buffer.alloc(plain.length);
        for (let i = 0; i < plain.length; i++) this._tcp_key[i] = plain[i] ^ key[i];
        this._request_count = 0;
        this._response_count = 0;
        return this._tcp_key;
    }
    encode_8370(data, msgtype) {
        let header = Buffer.from([0x83, 0x70]);
        let size = data.length, padding = 0;
        if ([MSGTYPE_ENCRYPTED_RESPONSE, MSGTYPE_ENCRYPTED_REQUEST].includes(msgtype)) {
            if ((size + 2) % 16 !== 0) {
                padding = 16 - ((size + 2) & 0xf);
                size += padding + 32;
                data = Buffer.concat([data, crypto.randomBytes(padding)]);
            }
        }
        header = Buffer.concat([header, Buffer.alloc(2)]); // size placeholder
        header = Buffer.concat([header, Buffer.from([0x20, (padding << 4) | msgtype])]);
        data = Buffer.concat([Buffer.alloc(2), data]); // request count placeholder
        // TODO: request count handling
        if ([MSGTYPE_ENCRYPTED_RESPONSE, MSGTYPE_ENCRYPTED_REQUEST].includes(msgtype)) {
            const sign = crypto.createHash('sha256').update(Buffer.concat([header, data])).digest();
            data = Buffer.concat([this.aes_cbc_encrypt(data, this._tcp_key), sign]);
        }
        // set size
        header.writeUInt16BE(data.length, 2);
        return Buffer.concat([header, data]);
    }
    decode_8370(data) {
        if (data.length < 6) return [[], data];
        const header = data.slice(0, 6);
        if (header[0] !== 0x83 || header[1] !== 0x70) throw new Error('not an 8370 message');
        const size = header.readUInt16BE(2) + 8;
        let leftover = null;
        if (data.length < size) return [[], data];
        else if (data.length > size) {
            leftover = data.slice(size);
            data = data.slice(0, size);
        }
        if (header[4] !== 0x20) throw new Error('missing byte 4');
        const padding = header[5] >> 4;
        const msgtype = header[5] & 0xf;
        data = data.slice(6);
        if ([MSGTYPE_ENCRYPTED_RESPONSE, MSGTYPE_ENCRYPTED_REQUEST].includes(msgtype)) {
            const sign = data.slice(-32);
            data = data.slice(0, -32);
            data = this.aes_cbc_decrypt(data, this._tcp_key);
            if (!crypto.createHash('sha256').update(Buffer.concat([header, data])).digest().equals(sign)) throw new Error('sign does not match');
            if (padding) data = data.slice(0, -padding);
        }
        this._response_count = data.readUInt16BE(0);
        data = data.slice(2);
        if (leftover) {
            const [packets, incomplete] = this.decode_8370(leftover);
            return [[data].concat(packets), incomplete];
        }
        return [[data], Buffer.alloc(0)];
    }
}
// --- BEGIN: Portierung der Geräte-Basisklasse (device.py) ---
class MideaDevice {
    constructor(options) {
        this.ip = options.ip;
        this.port = options.port || 6444;
        this.token = Buffer.from(options.token, 'hex');
        this.key = Buffer.from(options.key, 'hex');
        this.protocol = options.protocol || 3;
        this.model = options.model || '';
        this.deviceId = options.deviceId || 0;
        this.deviceType = options.deviceType || 0xAC;
        this.subtype = options.subtype || 0;
        this.attributes = options.attributes || {};
        this._socket = null;
        this._security = new LocalSecurity();
        this._buffer = Buffer.alloc(0);
        this._protocol_version = 0;
        this._updates = [];
        this._is_run = false;
        this._available = true;
        this._appliance_query = true;
        this._refresh_interval = 30;
        this._heartbeat_interval = 10;
        this._default_refresh_interval = 30;
    }

    async connect(refreshStatus = true) {
        return new Promise((resolve, reject) => {
            this._socket = new net.Socket();
            this._socket.setTimeout(10000);
            this._socket.connect(this.port, this.ip, async () => {
                if (this.protocol === 3) {
                    try {
                        await this.authenticate();
                    } catch (e) {
                        this._available = false;
                        return reject(e);
                    }
                }
                if (refreshStatus) {
                    try {
                        await this.refreshStatus(true);
                    } catch (e) {}
                }
                this._available = true;
                resolve(true);
            });
            this._socket.on('error', (err) => {
                this._available = false;
                reject(err);
            });
        });
    }

    async authenticate() {
        const request = this._security.encode_8370(this.token, MSGTYPE_HANDSHAKE_REQUEST);
        this._socket.write(request);
        return new Promise((resolve, reject) => {
            this._socket.once('data', (response) => {
                if (response.length < 20) return reject(new Error('AuthException'));
                const resp = response.slice(8, 72);
                this._security.tcp_key(resp, this.key);
                resolve();
            });
        });
    }

    async refreshStatus(waitResponse = false) {
        // Hier müsste die build_query-Logik für das jeweilige Gerät implementiert werden
        // und die Nachrichten gesendet/empfangen werden
        // Platzhalter für AC-Geräte folgt in der nächsten Ausbaustufe
    }

    async disconnect() {
        if (this._socket) {
            this._socket.destroy();
            this._socket = null;
        }
        this._available = false;
    }

    // ... weitere Methoden wie sendMessage, parseMessage, setAttribute, etc. ...
}
// --- ENDE: Portierung der Geräte-Basisklasse ---

// --- BEGIN: Portierung der AC-spezifischen Klasse (ac/device.py) ---
class MideaACDevice extends MideaDevice {
    constructor(options) {
        super({
            ...options,
            deviceType: 0xAC,
            attributes: {
                prompt_tone: true,
                power: false,
                mode: 0,
                target_temperature: 24.0,
                fan_speed: 102,
                swing_vertical: false,
                swing_horizontal: false,
                smart_eye: false,
                dry: false,
                aux_heating: false,
                boost_mode: false,
                sleep_mode: false,
                frost_protect: false,
                comfort_mode: false,
                eco_mode: false,
                natural_wind: false,
                temp_fahrenheit: false,
                screen_display: false,
                screen_display_alternate: false,
                full_dust: false,
                indoor_temperature: null,
                outdoor_temperature: null,
                indirect_wind: false,
                indoor_humidity: null,
                breezeless: false,
                total_energy_consumption: null,
                current_energy_consumption: null,
                realtime_power: null,
                fresh_air_power: false,
                fresh_air_fan_speed: 0,
                fresh_air_mode: null,
                fresh_air_1: null,
                fresh_air_2: null
            }
        });
        this._fresh_air_version = null;
        this._default_temperature_step = 0.5;
        this._temperature_step = null;
        this._used_subprotocol = false;
        this._bb_sn8_flag = false;
        this._bb_timer = false;
        this._power_analysis_method = 1;
    }
    // Hier folgen Methoden wie build_query, process_message, set_attribute, ...
}
// --- ENDE: Portierung der AC-spezifischen Klasse ---

// --- BEGIN: Nachrichtenklassen für AC (vereinfachte Portierung) ---
function buildQueryAC(protocolVersion) {
    // MessageQuery, MessageNewProtocolQuery, MessagePowerQuery
    // Für Demo: Nur ein einfaches Query
    return [Buffer.from([0x41, 0x81, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, crc8([0x41, 0x81, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])])];
}

MideaACDevice.prototype.build_query = function() {
    return buildQueryAC(this._protocol_version);
};

MideaACDevice.prototype.refreshStatus = async function(waitResponse = false) {
    const queries = this.build_query();
    for (const query of queries) {
        // Sende Query
        let msg = this._security.encode_8370(query, MSGTYPE_ENCRYPTED_REQUEST);
        this._socket.write(msg);
        if (waitResponse) {
            await new Promise((resolve, reject) => {
                this._socket.once('data', (data) => {
                    // Hier müsste parseMessage implementiert werden
                    // Für Demo: Nur Logging
                    // TODO: parseMessage(data)
                    resolve();
                });
            });
        }
    }
};
// --- ENDE: Nachrichtenklassen für AC ---

// --- BEGIN: parseMessage und Statusverarbeitung (vereinfachte Demo) ---
MideaACDevice.prototype.parseMessage = function(data) {
    // Hier müsste die vollständige Protokoll- und Payload-Entschlüsselung erfolgen
    // Für Demo: Wir loggen nur die empfangenen Daten
    // TODO: Protokoll-Parsing und Status-Update
    console.log('Empfangene Daten:', data.toString('hex'));
    // Beispiel: Status extrahieren und in this.attributes speichern
    // this.attributes.power = ...
    // this.attributes.target_temperature = ...
};
// --- ENDE: parseMessage ---

// --- BEGIN: Erweiterung parseMessage für Status-Update ---
MideaACDevice.prototype.parseMessage = function(data) {
    // Beispielhafte Entschlüsselung und Status-Update (vereinfachte Demo)
    // In der echten Portierung muss hier das Protokoll und die Payload wie in Python verarbeitet werden!
    try {
        // Entschlüsselung (Demo: Annahme, dass Daten direkt lesbar sind)
        // In echt: Protokoll-Parsing, z.B. mit decode_8370, dann Payload-Parsing
        // Hier nur ein Dummy-Status-Update:
        this.attributes.power = true; // Dummy
        this.attributes.target_temperature = 22; // Dummy
        // ... weitere Attribute ...
    } catch (e) {
        console.error('Fehler beim Parsen der Nachricht:', e);
    }
};
// --- ENDE: Erweiterung parseMessage ---

// --- BEGIN: Vollständige Payload-Entschlüsselung und Status-Parsing für AC ---
MideaACDevice.prototype.parseMessage = function(data) {
    try {
        // 1. 8370-Protokoll entschlüsseln
        let messages, buffer;
        if (this.protocol === 3) {
            [messages, buffer] = this._security.decode_8370(Buffer.from(data));
        } else {
            // V2-Protokoll nicht implementiert
            messages = [Buffer.from(data)];
        }
        if (!messages || messages.length === 0) return;
        for (const message of messages) {
            // 2. Payload extrahieren (ab Offset 40, -16 für Signatur)
            if (message.length > 56) {
                const cryptographic = message.slice(40, -16);
                if (cryptographic.length % 16 === 0) {
                    const decrypted = this._security.aes_decrypt(cryptographic);
                    // 3. Statusbytes parsen (vereinfachtes Beispiel für AC)
                    // Siehe Python: MessageACResponse, XA0MessageBody, etc.
                    // Hier: Power, Temperatur, Modus, Lüfter, Swing
                    if (decrypted.length > 10) {
                        this.attributes.power = (decrypted[1] & 0x1) > 0;
                        this.attributes.target_temperature = ((decrypted[1] & 0x3E) >> 1) - 4 + 16.0 + ((decrypted[1] & 0x40) ? 0.5 : 0.0);
                        this.attributes.mode = (decrypted[2] & 0xe0) >> 5;
                        this.attributes.fan_speed = decrypted[3] & 0x7f;
                        this.attributes.swing_vertical = (decrypted[7] & 0xC) > 0;
                        this.attributes.swing_horizontal = (decrypted[7] & 0x3) > 0;
                        // ... weitere Attribute nach Python-Logik ...
                    }
                }
            }
        }
    } catch (e) {
        console.error('Fehler beim Parsen der Nachricht:', e);
    }
};
// --- ENDE: Vollständige Payload-Entschlüsselung und Status-Parsing ---

// --- ENDE: Verschlüsselung und Protokoll ---

// --- BEGIN: Export der neuen Klassen ---
module.exports = {
    MideaDevice,
    MideaACDevice,
    LocalSecurity,
    crc8
};
// --- ENDE: Export ---

// --- BEGIN: Set-Kommandos für AC-Geräte (z.B. Temperatur, Modus, Power) ---
MideaACDevice.prototype.setPower = async function(on) {
    // Beispiel: Power setzen
    // Hier müsste ein entsprechendes Set-Command gebaut und gesendet werden
    // Für Demo: Wir setzen nur das Attribut
    this.attributes.power = !!on;
    // TODO: Sende Set-Command an das Gerät
};

MideaACDevice.prototype.setTemperature = async function(temp) {
    // Beispiel: Temperatur setzen
    this.attributes.target_temperature = temp;
    // TODO: Sende Set-Command an das Gerät
};

MideaACDevice.prototype.setMode = async function(mode) {
    // Beispiel: Modus setzen
    this.attributes.mode = mode;
    // TODO: Sende Set-Command an das Gerät
};

MideaACDevice.prototype.setFanSpeed = async function(speed) {
    // Beispiel: Lüftergeschwindigkeit setzen
    this.attributes.fan_speed = speed;
    // TODO: Sende Set-Command an das Gerät
};

MideaACDevice.prototype.setSwing = async function(vertical, horizontal) {
    this.attributes.swing_vertical = !!vertical;
    this.attributes.swing_horizontal = !!horizontal;
    // TODO: Sende Set-Command an das Gerät
};
// --- ENDE: Set-Kommandos für AC-Geräte ---

// --- BEGIN: setAttribute universell für AC-Geräte ---
MideaACDevice.prototype.setAttribute = async function(attr, value) {
    // Setzt ein beliebiges Attribut und sendet ggf. ein Set-Command
    this.attributes[attr] = value;
    // TODO: Sende Set-Command an das Gerät, je nach Attribut
    // Beispiel: if (attr === 'power') ...
};
// --- ENDE: setAttribute universell ---
