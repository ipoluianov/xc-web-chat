import xchg from "./xchg";

export default function makeXchgSimpleServer() {

    peer.onAuth = function (authData) {
        // no auth
    };

    peer.onCall = function (funcName, funcParameter) {
        return new TextEncoder().encode("42-42-42:" + funcName);
    };

    peer.start();

    return peer;
}
