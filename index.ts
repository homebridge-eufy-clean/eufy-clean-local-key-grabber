/**
From Android Eufy App.
*/
EUFY_CLIENT_ID = "eufyhome-app"
EUFY_CLIENT_SECRET = "GQCpr9dSp3uQpsOMgJ4xQ"

/**
From capturing traffic.
*/
EUFY_BASE_URL = "https://home-api.eufylife.com/v1/"

/** 
These are presumably obtained from the Android device's status.
*/
PLATFORM = "sdk_gphone64_arm64"
LANGUAGE = "en"
TIMEZONE = "Europe/London"

/**
From Eufy Home Android app.
*/
TUYA_CLIENT_ID = "yx5v9uc3ef9wg3v9atje"

/**
From testing it seems like any region is fine for initial logins.
The login response then contains the proper URL which should be used for subsequent requests.
*/
TUYA_INITIAL_BASE_URL = "https://a1.tuyaeu.com"

/**
# Eufy Home "TUYA_SMART_SECRET" Android app metadata value
*/
APPSECRET = "s8x78u7xwymasd9kqa7a73pjhxqsedaj"

/**
Obtained using instructions at https://github.com/nalajcie/tuya-sign-hacking
*/
BMP_SECRET = "cepev5pfnhua4dkqkdpmnrdxx378mpjr"

/**
Turns out this is not used by the Eufy app but this is from the Eufy Home app in case it's useful
APP_CERT_HASH = "A4:0D:A8:0A:59:D1:70:CA:A9:50:CF:15:C1:8C:45:4D:47:A3:9B:26:98:9D:8B:64:0E:CD:74:5B:A7:1B:F5:DC"
*/

/**
# hmac_key = f'{APP_CERT_HASH}_{BMP_SECRET}_{APPSECRET}'.encode('utf-8')
# turns out this app just uses "A" instead of the app's certificate hash
*/
EUFY_HMAC_KEY = f"A_{BMP_SECRET}_{APPSECRET}".encode("utf-8")

/**
From https://github.com/mitchellrj/eufy_robovac/issues/1
*/
TUYA_PASSWORD_KEY = bytearray([36, 78, 109, 138, 86, 172, 135, 145, 36, 67, 45, 139, 108, 188, 162, 196])
TUYA_PASSWORD_IV = bytearray([119, 36, 86, 242, 167, 102, 76, 243, 57, 44, 53, 151, 233, 62, 87, 71])

import math
from hashlib import md5

from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .constants import TUYA_PASSWORD_IV, TUYA_PASSWORD_KEY


def unpadded_rsa(key_exponent: int, key_n: int, plaintext: bytes) -> bytes:
    # RSA with no padding, as per https://github.com/pyca/cryptography/issues/2735#issuecomment-276356841
    keylength = math.ceil(key_n.bit_length() / 8)
    input_nr = int.from_bytes(plaintext, byteorder="big")
    crypted_nr = pow(input_nr, key_exponent, key_n)
    return crypted_nr.to_bytes(keylength, byteorder="big")


def shuffled_md5(value: str) -> str:
    # shuffling the hash reminds me of https://security.stackexchange.com/a/25588
    # from https://github.com/TuyaAPI/cloud/blob/9b108f4d347c81c3fd6d73f3a2bb08a646a2f6e1/index.js#L99
    _hash = md5(value.encode("utf-8")).hexdigest()
    return _hash[8:16] + _hash[0:8] + _hash[24:32] + _hash[16:24]


TUYA_PASSWORD_INNER_CIPHER = Cipher(
    algorithms.AES(TUYA_PASSWORD_KEY), modes.CBC(TUYA_PASSWORD_IV), backend=openssl_backend,
)



const eufyClient = new EufyHomeSession(process.argv[2], process.argv[3]);
const userInfo = eufyClient.getUserInfo();
const tuyaClient = new TuyaAPISession(`eh-${userInfo.id}`, userInfo.phone_code);

tuyaClient.listHomes().forEach(home => {
    console.log("Home:", home.groupId);
    tuyaClient.listDevices(home.groupId).forEach(device => {
        console.log(`Device: ${device.name}, device ID ${device.devId}, local key ${device.localKey}`);
    });
});


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
};

const DEFAULT_TUYA_HEADERS = {
    "User-Agent": "TY-UA=APP/Android/2.4.0/SDK/null"
};

const SIGNATURE_RELEVANT_PARAMETERS = new Set([
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
]);

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

class EufyHomeSession {
    base_url: string | null = null;
    email: string | null = null;
    password: string | null = null;

    constructor(email: string, password: string) {
        this.session = requests.session();
        this.session.headers = {...DEFAULT_EUFY_HEADERS};
        this.base_url = EUFY_BASE_URL;
        this.email = email;
        this.password = password;
    }

    url(path: string): string {
        return urljoin(this.base_url, path);
    }

    login(email: string, password: string): void {
        const resp = this.session.post(
            this.url("user/email/login"),
            {
                json: {
                    "client_Secret": EUFY_CLIENT_SECRET,
                    "client_id": EUFY_CLIENT_ID,
                    "email": email,
                    "password": password,
                },
            },
        );
        resp.raise_for_status();
        const data = resp.json();
        const access_token = data["access_token"];
        const user_id = data["user_info"]["id"];
        const new_base_url = data["user_info"]["request_host"];
        this.session.headers["uid"] = user_id;
        this.session.headers["token"] = access_token;
        this.base_url = new_base_url;
    }

    _request(...args: any[]): any {
        if (!this.session.headers["token"] || !this.session.headers["uid"]) {
            this.login(this.email, this.password);
        }
        const resp = this.session.request(...args);
        resp.raise_for_status();
        return resp.json();
    }

    get_devices(): any[] {
        return this._request("GET", this.url("device/v2")).get("devices", []);
    }

    get_user_info(): any {
        return this._request("GET", this.url("user/info"))["user_info"];
    }
}

class TuyaAPISession {
    username: string | null = null;
    country_code: string | null = null;
    session_id: string | null = null;

    constructor(username: string, country_code: string) {
        this.session = requests.session();
        this.session.headers = {...DEFAULT_TUYA_HEADERS};
        this.default_query_params = {...DEFAULT_TUYA_QUERY_PARAMS};
        this.default_query_params["deviceId"] = this.device_id = this.generate_new_device_id();
        this.username = username;
        this.country_code = country_code;
        this.base_url = TUYA_INITIAL_BASE_URL;
    }

    url(path: string): string {
        return urljoin(this.base_url, path);
    }

    static generate_new_device_id(): string {
        const expected_length = 44;
        const base64_characters = string.ascii_letters + string.digits;
        const device_id_dependent_part = "8534c8ec0ed0";
        return device_id_dependent_part + "".join(
            (random.choice(base64_characters) for _ in range(expected_length - len(device_id_dependent_part)))
        );
    }

    static encode_post_data(data: object): string {
        return json.dumps(data, separators=(",", ":")) if data else "";
    }

    static get_signature(query_params: object, encoded_post_data: string): string {
        query_params = {...query_params};
        if (encoded_post_data) {
            query_params["postData"] = encoded_post_data;
        }
        const sorted_pairs = sorted(query_params.items());
        const filtered_pairs = filter((p: any) => p[0] && p[0] in SIGNATURE_RELEVANT_PARAMETERS, sorted_pairs);
        const mapped_pairs = map(
            (p: any) => p[0] + "=" + (shuffled_md5(p[1]) if p[0] == "postData" else p[1]),
            filtered_pairs,
        );
        const message = "||".join(mapped_pairs);
        return hmac.HMAC(EUFY_HMAC_KEY, message.encode("utf-8"), sha256).hexdigest();
    }

    _request(
        action: string,
        version: string = "1.0",
        data: object = null,
        query_params: object = null,
        _requires_session: boolean = true,
    ): any {
        if (!this.session_id && _requires_session) {
            this.acquire_session();
        }
        const current_time = time.time();
        const request_id = uuid.uuid4();
        const extra_query_params = {
            "time": str(int(current_time)),
            "requestId": str(request_id),
            "a": action,
            "v": version,
            ...(query_params || {}),
        };
        query_params = {...this.default_query_params, ...extra_query_params};
        const encoded_post_data = this.encode_post_data(data);
        const resp = this.session.post(
            this.url("/api.json"),
            {
                params: {
                    ...query_params,
                    "sign": this.get_signature(query_params, encoded_post_data),
                },
                data: {"postData": encoded_post_data} if encoded_post_data else null,
            },
        );
        resp.raise_for_status();
        const data = resp.json();
        if (!("result" in data)) {
            throw new Exception(`No 'result' key in the response - the entire response is ${data}.`);
        }
        return data["result"];
    }

    request_token(username: string, country_code: string): any {
        return this._request(
            action="tuya.m.user.uid.token.create",
            data={"uid": username, "countryCode": country_code},
            _requires_session=false,
        );
    }

    determine_password(username: string): string {
        const new_uid = username;
        const padded_size = 16 * math.ceil(len(new_uid) / 16);
        const password_uid = new_uid.zfill(padded_size);
        const encryptor = TUYA_PASSWORD_INNER_CIPHER.encryptor();
        const encrypted_uid = encryptor.update(password_uid.encode("utf8"));
        encrypted_uid += encryptor.finalize();
        return md5(encrypted_uid.hex().upper().encode("utf-8")).hexdigest();
    }

    request_session(username: string, country_code: string): any {
        const password = this.determine_password(username);
        const token_response = this.request_token(username, country_code);
        const encrypted_password = unpadded_rsa(
            key_exponent=int(token_response["exponent"]),
            key_n=int(token_response["publicKey"]),
            plaintext=password.encode("utf-8"),
        );
        const data = {
            "uid": username,
            "createGroup": true,
            "ifencrypt": 1,
            "passwd": encrypted_password.hex(),
            "countryCode": country_code,
            "options": '{"group": 1}',
            "token": token_response["token"],
        };
        const session_response = this._request(
            action="tuya.m.user.uid.password.login.reg",
            data=data,
            _requires_session=false,
        );
        return session_response;
    }

    acquire_session(): void {
        const session_response = this.request_session(this.username, this.country_code);
        this.session_id = this.default_query_params["sid"] = session_response["sid"];
        this.base_url = session_response["domain"]["mobileApiUrl"];
    }

    list_homes(): any {
        return this._request(action="tuya.m.location.list", version="2.1");
    }

    list_devices(home_id: string): any {
        const ownDevices = this._request(
            action="tuya.m.my.group.device.list",
            version="1.0",
            query_params={"gid": home_id});
        const sharedDevices = this._request(
            action="tuya.m.my.shared.device.list",
            version="1.0");
        return ownDevices + sharedDevices;
    }
}


