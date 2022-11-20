import xchg from "./xchg";

export default function makeXchgSimpleServer() {
    var peer = xchg.makeXPeer();

    peer.onAuth = function (authData) {
        console.log("SERVER authData", authData);
        var authDataString = new TextDecoder().decode(authData);
        console.log("SERVER authgDataString", authDataString);
        if (authDataString !== "pass42") {
            throw "!auth ERROR!"
        }
    };

    peer.onCall = function (funcName, funcParameter) {
        return new TextEncoder().encode("42-42-42:" + funcName);
    };

    peer.start();

    return peer;
}
