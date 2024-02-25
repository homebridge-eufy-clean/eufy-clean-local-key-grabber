const EUFY_CLIENT_ID = "eufyhome-app";
const EUFY_CLIENT_SECRET = "GQCpr9dSp3uQpsOMgJ4xQ";

const EUFY_BASE_URL = "https://home-api.eufylife.com/v1/";

const PLATFORM = "sdk_gphone64_arm64";
const LANGUAGE = "en";
const TIMEZONE = "Europe/London";

const TUYA_CLIENT_ID = "yx5v9uc3ef9wg3v9atje";
const TUYA_INITIAL_BASE_URL = "https://a1.tuyaeu.com";

const APPSECRET = "s8x78u7xwymasd9kqa7a73pjhxqsedaj";
const BMP_SECRET = "cepev5pfnhua4dkqkdpmnrdxx378mpjr";

const EUFY_HMAC_KEY = `A_${BMP_SECRET}_${APPSECRET}`;

const TUYA_PASSWORD_KEY = Uint8Array.from([36, 78, 109, 138, 86, 172, 135, 145, 36, 67, 45, 139, 108, 188, 162, 196]);
const TUYA_PASSWORD_IV = Uint8Array.from([119, 36, 86, 242, 167, 102, 76, 243, 57, 44, 53, 151, 233, 62, 87, 71]);

import crypto from 'crypto';
import * as uuid from 'uuid';

function md5(data: string): string {
    return crypto.createHash('md5').update(data).digest('hex');
}

function unpadded_rsa(key_exponent: number, key_n: number, plaintext: Buffer): Buffer {
    // RSA with no padding
    const keylength = Math.ceil((key_n.toString(2).length) / 8);
    const input_nr = parseInt(plaintext.toString('hex'), 16);
    const crypted_nr = Math.pow(input_nr, key_exponent) % key_n;
    const buffer = Buffer.alloc(keylength);
    buffer.writeUIntBE(crypted_nr, 0, keylength);
    return buffer;
}

function shuffled_md5(value: string): string {
    const _hash = crypto.createHash('md5').update(value, 'utf8').digest('hex');
    return _hash.substring(8, 16) + _hash.substring(0, 8) + _hash.substring(24, 32) + _hash.substring(16, 24);
}

interface ResponseType {
    devices: any[]; // replace 'any' with the actual type of the devices
    user_info?: any;
    // include other properties of the response object if necessary
}

const DEFAULT_EUFY_HEADERS = {
    "User-Agent": "EufyHome-Android-2.4.0",
    "timezone": TIMEZONE,
    "category": "Home",
    "token": "",
    "uid": "",
    "openudid": PLATFORM,
    "clientType": "2",
    "language": LANGUAGE,
    "country": "US",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
};

const DEFAULT_TUYA_HEADERS = {
    "User-Agent": "TY-UA=APP/Android/2.4.0/SDK/null"
};

const SIGNATURE_RELEVANT_PARAMETERS = [
    "a",
    "v",
    "lat",
    "lon",
    "lang",
    "deviceId",
    "appVersion",
    "ttid",
    "isH5",
    "h5Token",
    "os",
    "clientId",
    "postData",
    "time",
    "requestId",
    "et",
    "n4h5",
    "sid",
    "sp",
];

const DEFAULT_TUYA_QUERY_PARAMS = {
    "appVersion": "2.4.0",
    "deviceId": "",
    "platform": PLATFORM,
    "clientId": TUYA_CLIENT_ID,
    "lang": LANGUAGE,
    "osSystem": "12",
    "os": "Android",
    "timeZoneId": TIMEZONE,
    "ttid": "android",
    "et": "0.0.1",
    "sdkVersion": "3.0.8cAnker",
};

import axios from 'axios';

export class TuyaAPISession {
    username: string | null = null;
    country_code: string | null = null;
    session_id: string | null = null;
    session: any;
    base_url: string;
    action: string = '';
    version: string  = '';

    constructor(username: string, country_code: string) {
        this.session = axios.create({
            headers: DEFAULT_TUYA_HEADERS
        });
        this.username = username;
        this.country_code = country_code;
        this.base_url = TUYA_INITIAL_BASE_URL;
    }

    url(path: string) {
        return new URL(path, this.base_url).toString();
    }

    generate_new_device_id() {
        const expected_length = 44;
        const base64_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        const device_id_dependent_part = "8534c8ec0ed0";
        const random_part = Array.from({length: expected_length - device_id_dependent_part.length}, () => base64_characters[Math.floor(Math.random() * base64_characters.length)]).join('');

        return device_id_dependent_part + random_part;
    }

    encode_post_data(data: any) {
        return JSON.stringify(data);
    }

    get_signature(query_params: any, encoded_post_data: string) {
        const hmac = crypto.createHmac('sha256', EUFY_HMAC_KEY);
        const sorted_pairs = Object.entries(query_params).sort();
        const filtered_pairs = sorted_pairs.filter(([key, value]) => SIGNATURE_RELEVANT_PARAMETERS.includes(key));
        const mapped_pairs = filtered_pairs.map(([key, value]) => {
            if (key === "postData") {
                return `${key}=${shuffled_md5(String(value))}`;
            } else {
                return `${key}=${value}`;
            }
        });

        const message = mapped_pairs.join("||");
        hmac.update(message);
        return hmac.digest('hex');
    }

    async _request(method: string, path: string, data: any = null) {
        if (!this.session_id) {
            await this.acquire_session();
        }

        const current_time = Math.floor(Date.now() / 1000);
        const request_id = uuid.v4();
        
        const extra_query_params = {
            "time": current_time.toString(),
            "requestId": request_id.toString(),
            "a": this.action,
            "v": this.version,
        };

        const query_params = {...DEFAULT_TUYA_QUERY_PARAMS, ...extra_query_params};

        
        const encoded_post_data = this.encode_post_data(data);

        const resp = await this.session.post(
            this.url("/api.json"),
            {
                params: {
                    ...query_params,
                    "sign": this.get_signature(query_params, encoded_post_data)
                },
                data: {
                    "postData": encoded_post_data
                }
            }
        );

        return resp.data;
    }

    async request_token(username: string, country_code: string) {
        const path = `some/path/${username}/${country_code}`; // replace 'some/path/' with the actual path
        return this._request(
            "tuya.m.user.uid.token.create",
            path,
            false
        );
    }

    determine_password(username: string) {
        const new_uid = username;
        const padded_size = 16 * Math.ceil(new_uid.length / 16);
        const password_uid = new_uid.padStart(padded_size, '0');
        const TUYA_PASSWORD_INNER_CIPHER = crypto.createCipheriv('aes-256-cbc', TUYA_PASSWORD_KEY, TUYA_PASSWORD_IV);
    
        const encrypted_uid = Buffer.concat([TUYA_PASSWORD_INNER_CIPHER.update(password_uid, 'utf8'), TUYA_PASSWORD_INNER_CIPHER.final()]);
        const encrypted_uid_string = encrypted_uid.toString('hex'); // convert buffer to string
        return md5(encrypted_uid_string.toUpperCase()).toString();
    }

    async request_session(username: string, country_code: string) {
        const password = this.determine_password(username);
        const token_response = await this.request_token(username, country_code);

        const encrypted_password = unpadded_rsa(
            parseInt(token_response["exponent"]),
            parseInt(token_response["publicKey"]),
            Buffer.from(password, 'utf8')
        );

        const data = {
            "uid": username,
            "createGroup": true,
            "ifencrypt": 1,
            "passwd": encrypted_password.toString('hex'),
            "countryCode": country_code,
            "options": '{"group": 1}',
            "token": token_response["token"],
        };

        return this._request(
            "tuya.m.user.uid.password.login.reg",
            JSON.stringify(data)
        );
    }
    
    async acquire_session() {
        if (this.username === null || this.country_code === null) {
            throw new Error("Username or country code is null");
        }
        const session_response = await this.request_session(this.username, this.country_code);
        this.session_id = session_response["sid"];
        this.base_url = session_response["domain"]["mobileApiUrl"];
    }

    async list_homes() {
        return this._request("tuya.m.location.list", "2.1");
    }

    async list_devices(home_id: string) {
        const ownDevices = await this._request(
            "tuya.m.my.group.device.list",
            "1.0",
            {"gid": home_id}
        );

        const sharedDevices = await this._request(
            "tuya.m.my.shared.device.list",
            "1.0"
        );

        return ownDevices.concat(sharedDevices);
    }
}

export class EufyHomeSession {
    base_url: string | null = null;
    email: string | null = null;
    password: string | null = null;
    session: any;

    encode_post_data(data: any) {
        return JSON.stringify(data);
    }

    constructor(email: string, password: string) {
        this.session = axios.create({
            headers: DEFAULT_EUFY_HEADERS
        });
        this.base_url = EUFY_BASE_URL;
        this.email = email;
        this.password = password;
    }

    url(path: string) {
        if (this.base_url === null) {
            throw new Error("Base URL is null");
        }
        return new URL(path, this.base_url).toString();
    }

    async login(email: string, password: string) {
        const resp = await this.session.post(
            this.url("user/email/login"),
            {
                "client_Secret": EUFY_CLIENT_SECRET,
                "client_id": EUFY_CLIENT_ID,
                "email": email,
                "password": password,
            }
        );

        const data = resp.data;

        const access_token = data["access_token"];
        const user_id = data["user_info"]["id"];
        const new_base_url = data["user_info"]["request_host"];

        this.session.headers["uid"] = user_id;
        this.session.headers["token"] = access_token;
        this.base_url = new_base_url;
    }


    get_signature(query_params: any, encoded_post_data: string) {
        const hmac = crypto.createHmac('sha256', EUFY_HMAC_KEY);
        const sorted_pairs = Object.entries(query_params).sort();
        const filtered_pairs = sorted_pairs.filter(([key, value]) => SIGNATURE_RELEVANT_PARAMETERS.includes(key));
        const mapped_pairs = filtered_pairs.map(([key, value]) => {
            if (key === "postData") {
                return `${key}=${shuffled_md5(String(value))}`;
            } else {
                return `${key}=${value}`;
            }
        });

        const message = mapped_pairs.join("||");
        hmac.update(message);
        return hmac.digest('hex');
    }

    async _request(method: string, path: string, data: any = null) : Promise<ResponseType> {
        if (!this.session.headers["token"] || !this.session.headers["uid"]) {
            if (this.email === null || this.password === null) {
                throw new Error("Email or password is null");
            }
            await this.login(this.email, this.password);
        }
        
        const query_params = {};
        const encoded_post_data = this.encode_post_data(data);

        const resp = await this.session.post(
            this.url("/api.json"),
            {
                params: {
                    ...query_params,
                    "sign": this.get_signature(query_params, encoded_post_data)
                },
                data: {
                    "postData": encoded_post_data
                }
            }
        );
    
        return resp.data;
    }

    async get_devices() {
        const resp = await this._request("GET", "device/v2") as ResponseType;
        return resp.devices || [];
    }

    async get_user_info() {
        const resp = await this._request("GET", "user/info") as ResponseType;
        return resp.user_info;
    }
}

