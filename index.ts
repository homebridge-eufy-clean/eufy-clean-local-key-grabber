import { EufyHomeSession, TuyaAPISession } from './clients';

async function main() {
    const email = 'hgelderbloem@icloud.com';
    const password = 'bewbA0-mabmyg-cuktac';

    const eufySession = new EufyHomeSession(email, password);
    eufySession.Initialize(email, password)

    let eufyClient = new EufyHomeSession(process.argv[2], process.argv[3]);
    let userInfo = await eufyClient.get_user_info();

    let tuyaClient = new TuyaAPISession(`eh-${userInfo["id"]}`, userInfo["phone_code"]);

    let homes = await tuyaClient.list_homes();
    for (let home of homes) {
        console.log("Home:", home["groupId"]);

        let devices = await tuyaClient.list_devices(home["groupId"]);
        for (let device of devices) {
            console.log(`Device: ${device['name']}, device ID ${device['devId']}, local key ${device['localKey']}`);
        }
    }
}

main();