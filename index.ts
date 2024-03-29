import { EufyHomeSession, TuyaAPISession } from './clients';

async function main() {
    const email = '';
    const password = '';

    const eufySession = new EufyHomeSession(email, password);
    if (eufySession.email !== null && eufySession.password !== null) {
        await eufySession.login(eufySession.email, eufySession.password);
    }
    //await eufySession.login(eufySession.email, eufySession.password);
    const userInfo = await eufySession.get_user_info();
    console.log(userInfo)

    let eufyClient = new EufyHomeSession(process.argv[2], process.argv[3]);
    //let userInfo = await eufyClient.get_user_info();

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

main().catch((error) => {
    console.error(error);
});