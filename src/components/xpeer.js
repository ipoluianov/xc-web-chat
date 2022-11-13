import xchg from "./xchg";
import axios from "axios";
import { checkCompatEnabled } from "@vue/compiler-core";

export default function makeXPeer() {
    return {
        keyPair: {},
        counter: 0,
        remotePeers: {},
        incomingTransactions: {},
        localAddress: "",
        nonces: {},
        async start() {
            this.keyPair = await xchg.generateRSAKeyPair();
            this.localAddress = await xchg.addressFromPublicKey(this.keyPair.publicKey);
            console.log("start local address:", this.localAddress);
            this.timer = window.setInterval(this.backgroundWorker, 1000, this);
            this.nonces = xchg.makeNonces();
        },
        async stop() {
            window.clearInterval(this.timer)
        },
        backgroundWorker(ctx) {
            ctx.counter++;
            ctx.requestXchgrRead(ctx.localAddress);
        },
        call(address, func) {
            var remotePeer
            if (this.remotePeers[address] != undefined) {
                remotePeer = this.remotePeers[address];
            } else {
                remotePeer = makeRemotePeer(this.localAddress, address, this.keyPair);
                remotePeer.start();
                this.remotePeers[address] = remotePeer;
            }
            remotePeer.call(func);
        },

        afterId: 0,
        makeXchgrReadRequest(address) {
            if (address == undefined) {
                address = "";
            }
            address = address.replaceAll("#", "");
            var myBuffer = new ArrayBuffer(46);
            var view1 = new DataView(myBuffer);
            view1.setBigUint64(0, BigInt(this.afterId), true); // AfterId
            view1.setBigUint64(8, BigInt(1024 * 1024), true); // MaxSize
            var addressBS = xchg.addressToAddressBS(address);
            if (addressBS.byteLength != 30) {
                throw "wrong address length";
            }
            var view2 = new DataView(addressBS);
            for (var i = 0; i < 30; i++) {
                view1.setInt8(i + 16, view2.getInt8(i));
            }
            var ww = xchg.arrayBufferToBase64(myBuffer)
            return ww
        },

        requestXchgrReadProcessing: false,
        async requestXchgrRead(address) {
            if (this.requestXchgrReadProcessing) {
                return;
            }

            this.requestXchgrReadProcessing = true;
            var receivedData;
            try {
                var frame = this.makeXchgrReadRequest(address);
                const formData = new FormData();
                formData.append('d', frame);
                const response = await axios.post("http://localhost:8084/api/r", formData, {
                    headers: formData.headers
                },);
                console.log("received data len:", response.data.length);
                receivedData = response.data;

            } catch (ex) {
                console.log(ex);
                this.requestXchgrReadProcessing = false;
            }
            this.requestXchgrReadProcessing = false;

            // Process frames
            var resultBA = xchg.base64ToArrayBuffer(receivedData)
            var view = new DataView(resultBA);
            var bytes = new Uint8Array(resultBA);
            var lastId = view.getBigUint64(0, true);
            console.log(lastId)

            this.afterId = Number(lastId)
            var offset = 8
            var size = view.byteLength;
            while (offset < size) {
                if (offset + 128 <= size) {
                    var frameLen = view.getUint32(offset, true);
                    if (offset + frameLen <= size) {
                        var frame = bytes.subarray(offset, offset + frameLen);
                        this.processFrame(frame.buffer.slice(frame.byteOffset, frame.byteOffset + frameLen));
                    } else {
                        break;
                    }
                    offset += frameLen;
                } else {
                    break;
                }
            }
            return
        },
        processFrame(frame) {
            var t = this.parseTransaction(frame);
            if (t.frameType == 0x10) {
                this.processFrame10(t);
            }
            if (t.frameType == 0x11) {
                this.processFrame11(t);
            }
            if (t.frameType == 0x20) {
                this.processFrame20(t);
            }
            if (t.frameType == 0x21) {
                this.processFrame21(t);
            }
        },
        processFrame10(t) {

            // Remove old incoming transactions
            var foundForDelete = true;
            while (foundForDelete) {
                foundForDelete = false;
                for (const trCode in this.incomingTransactions) {
                    var incomingTransaction = this.incomingTransactions[trCode]
                    if (Date.now() - incomingTransaction.beginDT > 10000) {
                        delete this.incomingTransactions[trCode];
                        foundForDelete = true;
                        break;
                    }
                }
            }

            var trCode = t.srcAddress + "/" + t.transactionId;
            var incomingTransaction = this.incomingTransactions[trCode];
            if (incomingTransaction == undefined) {
                incomingTransaction.length = 0;
                incomingTransaction.crc = 0;
                incomingTransaction.frameType = t.frameType;
                incomingTransaction.transactionId = t.transactionId;
                incomingTransaction.sessionId = t.sessionId;
                incomingTransaction.offset = t.offset;
                incomingTransaction.totalSize = t.totalSize;
                incomingTransaction.srcAddress = t.srcAddress;
                incomingTransaction.destAddress = t.destAddress;
                this.incomingTransactions[trCode] = incomingTransaction;
            }

            incomingTransaction.appendReceivedData(t.data);

            if (incomingTransaction.complete) {
                incomingTransaction.data = incomingTransaction.result;
                incomingTransaction.result = undefined;
            } else {
                return
            }

            delete this.incomingTransactions[trCode];

            var response = this.onEdgeReceivedCall(incomingTransaction.sessionId, incomingTransaction.data);
            if (response != undefined) {
                trResponse = xchg.makeTransaction();
                trResponse.frameType = 0x11;
                trResponse.transactionId = incomingTransaction.transactionId;
                trResponse.sessionId = incomingTransaction.sessionId;
                trResponse.offset = 0;
                trResponse.totalSize = response.length;
                trResponse.srcAddress = this.localAddress;
                trResponse.destAddress = incomingTransaction.srcAddress;

                var offset = 0;
                var blockSize = 1024;
                while (offset < trResponse.data.length) {
                    var currentBlockSize = blockSize;
                    restDataLen = trResponse.data.length - offset;
                    if (restDataLen < currentBlockSize) {
                        currentBlockSize = restDataLen;
                    }

                    trBlock = xchg.makeTransaction();
                    trBlock.frameType = 0x11;
                    trBlock.transactionId = trResponse.transactionId;
                    trBlock.sessionId = trResponse.sessionId;
                    trBlock.offset = offset;
                    trBlock.totalSize = response.length;
                    trBlock.srcAddress = trResponse.srcAddress;
                    trBlock.destAddress = trResponse.destAddress;
                    trBlock.data = trResponse.data.slice(offset, offset + currentBlockSize);

                    var responseFrameBlock = trBlock.serialize()
                    this.sendFrame(trBlock.destAddress, responseFrameBlock);
                    offset += currentBlockSize;
                }
            }

        },
        processFrame11(t) {
            var remotePeer = this.remotePeers[t.destAddress];
            if (remotePeer == undefined) {
                return
            }
            remotePeer.processFrame11(t);
        },
        async processFrame20(t) {
            if (t.data.length < 16) {
                return
            }

            var nonce = t.data.slice(0, 16)
            var nonceHash = await crypto.subtle.digest('SHA-256', nonce);
            var nonceView = new DataView(nonce);
            var addressStringBytes = t.data.slice(16);
            var address = new TextDecoder().decode(addressStringBytes);
            if (address !== this.localAddress) {
                return
            }

            var publicKeyBS = xchg.rsaExportPublicKey(c.keyPair.publicKey);
            var publicKeyBSView = new DataView(publicKeyBS);
            var signature = xchg.rsaSign(this.keyPair.privateKey, nonceHash);
            var signatureView = new DataView(signature);

            var response = new ArrayBuffer(16 + 256 + publicKeyBS.byteLength);
            var respView = new DataView();
            for (var i = 0; i < nonce.byteLength; i++) {
                respView.setInt8(i + nonceView.getInt8(i));
            }
            for (var i = 0; i < signature.byteLength; i++) {
                respView.setInt8(16 + isignatureView.getInt8(i));
            }
            for (var i = 0; i < publicKeyBS.byteLength; i++) {
                respView.setInt8(16 + 256 + i, publicKeyBSView.getInt8(i));
            }

            trResponse = xchg.makeTransaction();
            trResponse.frameType = 0x21;
            trResponse.transactionId = 0;
            trResponse.sessionId = 0;
            trResponse.offset = 0;
            trResponse.totalSize = response.byteLength;
            trResponse.srcAddress = this.localAddress;
            trResponse.destAddress = t.srcAddress;
            trResponse.data = response;

            var frResponse = trResponse.serialize();
            this.sendFrame(trResponse.destAddress, frResponse);
        },
        async processFrame21(t) {
            if (t.data.byteLength < 16 + 256) {
                return
            }

            var receivedNonce = t.data.slice(0, 16);

            console.log("nonce:", receivedNonce);

            var receivedPublicKeyBS = t.data.slice(16 + 256);
            var receivedPublicKey = await xchg.rsaImportPublicKey(receivedPublicKeyBS);
            var receivedAddress = await xchg.addressFromPublicKey(receivedPublicKey);
            var remotePeer = this.remotePeers[receivedAddress];
            if (remotePeer === undefined) {
                return
            }

            console.log("receivedAddress", receivedAddress)

            remotePeer.processFrame21(receivedNonce, receivedPublicKey);
        },
        parseTransaction(frame) {
            var t = {}
            var view = new DataView(frame)
            t.length = view.getUint32(0, true)
            t.crc = view.getUint32(4, true)
            t.frameType = view.getInt8(8);
            t.transactionId = view.getBigUint64(16, true);
            t.sessionId = view.getBigUint64(24, true);
            t.offset = view.getUint32(32, true);
            t.totalSize = view.getUint32(36, true);
            t.srcAddress = xchg.addressBSToAddress32(frame.slice(40, 70));
            t.destAddress = xchg.addressBSToAddress32(frame.slice(70, 100));
            t.data = frame.slice(128, frame.length);
            return t
        },
        async sendFrame(destAddress, frame) {
            const formData = new FormData();
            formData.append('d', frame);
            const response = await axios.post("http://localhost:8084/api/w", formData, {
                headers: formData.headers
            },);
        },

        onEdgeReceivedCall() {
        },

    };
}

function makeRemotePeer(localAddr, address, localKeys) {
    return {
        counter: 0,
        localKeys: localKeys,
        remoteAddress: address,
        localAddress: localAddr,
        sessionId: 0,
        remotePublicKey: undefined,
        nonces: {},
        authData: new ArrayBuffer(10),
        sessionNonceCounter: 0,
        nextTransactionId: 0,
        start() {
            this.nonces = xchg.makeNonces(1000);
            this.timer = window.setInterval(this.backgroundWorker, 200, this);
        },
        stop() {
            window.clearInterval(this.timer)
        },
        backgroundWorker(ctx) {
            //console.log("remotepeer " + ctx.remoteAddress + " = " + ctx.counter);
            //ctx.counter++;
        },
        async call() {
            console.log("RemotePeer call to ", this.remoteAddress);
            if (this.remotePublicKey === undefined) {
                await this.check();
            }

            if (this.sessionId === 0) {
                var authResult = await this.auth();
                if (!authResult) {
                    throw "auth failed";
                }
            }

            return this.regularCall(func, data, this.aesKey);
        },
        async check() {
            var enc = new TextEncoder();
            var addr = this.remoteAddress
            var remoteAddressBS = enc.encode(addr);
            var remoteAddressBSView = new DataView(remoteAddressBS.buffer);
            var request = new ArrayBuffer(16 + remoteAddressBS.byteLength);
            var requestView = new DataView(request);
            var nonce = await this.nonces.next();
            var nonceView = new DataView(nonce);
            for (var i = 0; i < 16; i++) {
                requestView.setUint8(i, nonceView.getUint8(i));
            }
            for (var i = 0; i < remoteAddressBS.byteLength; i++) {
                requestView.setUint8(16 + i, remoteAddressBSView.getUint8(i));
            }

            var t = xchg.makeTransaction();
            t.frameType = 0x20;
            t.transactionId = 0;
            t.sessionId = 0;
            t.offset = 0;
            t.totalSize = request.byteLength;
            t.srcAddress = this.localAddress;
            t.destAddress = this.remoteAddress;
            t.data = request;
            var frame = t.serialize()
            console.log("request", frame);

            this.sendFrame(t.destAddress, frame);
        },

        async sendFrame(destAddress, frame) {
            console.log("SEND FRAME FROM PEER", frame);
            var frame64 = xchg.arrayBufferToBase64(frame);
            console.log("SEND FRAME FROM PEER", frame64);
            const formData = new FormData();
            formData.append('d', frame64);
            const response = await axios.post("http://localhost:8084/api/w", formData, {
                headers: formData.headers
            },);
        },

        async processFrame21(receivedNonce, receivedPublicKey) {
            if (!this.nonces.check(receivedNonce)) {
                console.log("Wrong nonce", receivedNonce);
                return
            }

            this.remotePublicKey = receivedPublicKey;
        },

        async auth() {
            if (this.authProcessing) {
                return false;
            }
            this.authProcessing = true;
            var nonce = await this.regularCall("/xchg-get-nonce", new ArrayBuffer(0), new ArrayBuffer(0));
            var nonceView = new DataView(nonce);
            if (this.remotePublicKey === undefined) {
                return false;
            }

            var localPublicKeyBS = await xchg.rsaExportPublicKey();
            var localPublicKeyBSView = new DataView(localPublicKeyBS);
            var authDataView = new ArrayBuffer(this.authData);

            var authFrameSecret = new ArrayBuffer(16 + this.authData.byteLength);
            var authFrameSecretView = new DataView(authFrameSecret);
            for (var i = 0; i < 16; i++) {
                authFrameSecretView.setUint8(i, nonceView.getUint8(i));
            }
            for (var i = 0; i < this.authData.byteLength; i++) {
                authFrameSecretView.setUint8(16 + i, authDataView.getUint8(i));
            }

            var encryptedAuthFrame = await xchg.rsaEncrypt(this.remotePublicKey, authFrameSecret);
            var encryptedAuthFrameView = new DataView(encryptedAuthFrame);
            var authFrame = new ArrayBuffer(4 + localPublicKeyBS.byteLength + encryptedAuthFrame.byteLength);
            var authFrameView = new DataView(authFrame);
            authFrameView.setUint32(0, localPublicKeyBS.byteLength, true);
            for (var i = 0; i < localPublicKeyBS.byteLength; i++) {
                authFrameView.setUint8(4 + i, localPublicKeyBSView.getUint8(i));
            }
            for (var i = 0; i < encryptedAuthFrame.byteLength; i++) {
                authFrameView.setUint8(4 + localPublicKeyBS.byteLength + i, encryptedAuthFrameView.getUint8(i));
            }

            var result = await this.regularCall("/xchg-auth", authFrame, new ArrayBuffer(0), new ArrayBuffer(0));
            result = xchg.rsaDecrypt(result, this.localKeys.privateKey);
            if (result.length != 8 + 32) {
                return false;
            }

            var resultView = new DataView(result);

            this.sessionId = resultView.getBigUint64(0, true);
            this.aesKey = result.slice(8);
            return true;
        },

        async regularCall(func, data, aesKey) {
            var enc = new TextEncoder();
            var funcBS = enc.encode(func);
            if (funcBS.byteLength > 255) {
                return
            }

            var encrypted = false;
            if (this.localKeys === undefined) {
                return;
            }

            var sessionNonceCounter = this.sessionNonceCounter;
            this.sessionNonceCounter++;

            var frame = new ArrayBuffer(0);
            if (aesKey.byteLength == 32) {
                frame = new ArrayBuffer(8 + 1 + funcBS.byteLength + data.byteLength);
                var frameView = new DataView(frame);
                frameView.setBigUint64(0, sessionNonceCounter, true);
                frameView.setUint8(8, funcBS.byteLength);
                xchg.copyBA(frame, 9, funcBS);
                xchg.copyBA(frame, 9 + funcBS.byteLength, data);
                frame = xchg.pack(frame);
                frame = xchg.aesEncrypt(frame, aesKey);
                encrypted = true;
            } else {
                frame = new ArrayBuffer(1 + funcBS.byteLength + data.byteLength);
                frameView.setUint8(0, funcBS.byteLength);
                xchg.copyBA(frame, 1, funcBS);
                xchg.copyBA(frame, 1 + funcBS.byteLength, data);
            }

            var result = this.executeTransaction(this.sessionId, frame);

            if (encrypted) {
                result = xchg.aesDecrypt(result, aesKey);
                result = xchg.unpack(frame);
            }

            if (result.byteLength < 1) {
                return;
            }

            var resultData = new ArrayBuffer(0);
            var resultView = new DataView(result);
            if (resultView.getUint8(0) == 0) {
                // Success
                resultData = new ArrayBuffer(result.byteLength - 1);
                xchg.copyBA(resultData, 0, result, 1);
            }

            if (resultView.getUint8(0) == 1) {
                resultData = new ArrayBuffer(result.byteLength - 1);
                xchg.copyBA(resultData, 0, result, 1);
                var dec = new TextDecoder();
                throw dec.decode(resultData);
            }
        },

        async executeTransaction(sessionId, data) {
            var transactionId = c.nextTransactionId;
            c.nextTransactionId++;

            var t = xchg.makeTransaction();
            t.frameType = 0x10;
            t.transactionId = transactionId;
            t.sessionId = sessionId;
            t.offset = 0;
            t.totalSize = data.byteLength;
            t.data = data;
            t.srcAddress = this.localAddress;
            t.destAddress = this.remoteAddress;

            c.outgoingTransactions[transactionId] = t;

            var offset = 0;
            var blockSize = 1024;
            while (offset < data.byteLength) {
                var currentBlockSize = blockSize;
                var restDataLen = data.byteLength - offset;
                if (restDataLen < currentBlockSize) {
                    currentBlockSize = restDataLen;
                }

                var tBlock = xchg.makeTransaction();
                t.frameType = 0x10;
                t.transactionId = transactionId;
                t.sessionId = sessionId;
                t.offset = offset;
                t.totalSize = data.byteLength;
                t.data = data.slice(offset, offset + currentBlockSize);
                t.srcAddress = this.localAddress;
                t.destAddress = this.remoteAddress;
                var tBlockBA = t.serialize();

                this.sendFrame(t.destAddress, tBlockBA);

                for (var i = 0; i < 100; i++) {
                    if (t.complete) {
                        delete this.outgoingTransactions[transactionId];
                        if (t.err !== undefined) {
                            throw t.err
                        }

                        return t.result;
                    }
                    await sleep(10);
                }

                throw "transaction timeout";
            }
        },
    };
}
