import xchg from "./xchg";
import axios from "axios";

export default function makeXPeer() {
    return {
        keyPair: {},
        remotePeers: {},
        incomingTransactions: {},
        localAddress: "",
        nonces: {},
        sessions: {},
        nextSessionId: 1,
        async start() {
            this.keyPair = await xchg.generateRSAKeyPair();
            this.localAddress = await xchg.addressFromPublicKey(this.keyPair.publicKey);
            console.log("start local address:", this.localAddress);
            this.timer = window.setInterval(this.backgroundWorker, 100, this);
            this.nonces = xchg.makeNonces(1000);
        },
        async stop() {
            window.clearInterval(this.timer)
        },
        backgroundWorker(ctx) {
            ctx.requestXchgrRead(ctx.localAddress);
        },
        async call(address, func, data) {
            var remotePeer
            if (this.remotePeers[address] != undefined) {
                remotePeer = this.remotePeers[address];
            } else {
                remotePeer = makeRemotePeer(this.localAddress, address, this.keyPair);
                remotePeer.start();
                this.remotePeers[address] = remotePeer;
            }
            return await remotePeer.call(func, data);
        },

        afterId: 0,
        makeXchgrReadRequest(address) {
            if (address == undefined) {
                throw "makeXchgrReadRequest: address is undefined";
            }
            address = address.replaceAll("#", "");
            var buffer = new ArrayBuffer(8 + 8 + 30);
            var bufferView = new DataView(buffer);
            bufferView.setBigUint64(0, BigInt(this.afterId), true); // AfterId
            bufferView.setBigUint64(8, BigInt(1024 * 1024), true); // MaxSize
            var addressBS = xchg.addressToAddressBS(address);
            if (addressBS.byteLength != 30) {
                throw "wrong address length";
            }
            xchg.copyBA(buffer, 16, addressBS);
            return xchg.arrayBufferToBase64(buffer);
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

            this.afterId = Number(lastId)
            var offset = 8
            var size = view.byteLength;
            while (offset < size) {
                if (offset + 128 <= size) {
                    var frameLen = view.getUint32(offset, true);
                    if (offset + frameLen <= size) {
                        var frame = bytes.subarray(offset, offset + frameLen);
                        await this.processFrame(frame.buffer.slice(frame.byteOffset, frame.byteOffset + frameLen));
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
        async processFrame(frame) {
            var t = this.parseTransaction(frame);
            console.log("process frame", t);
            try {
                if (t.frameType == 0x10) {
                    await this.processFrame10(t);
                }
                if (t.frameType == 0x11) {
                    await this.processFrame11(t);
                }
                if (t.frameType == 0x20) {
                    await this.processFrame20(t);
                }
                if (t.frameType == 0x21) {
                    await this.processFrame21(t);
                }
            } catch (ex) {
                console.log("processFrame exception", ex);
            }
        },
        async processFrame10(t) {

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
                incomingTransaction = xchg.makeTransaction();
                incomingTransaction.beginDT = Date.now();
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

            incomingTransaction.appendReceivedData(t);

            if (incomingTransaction.complete) {
                incomingTransaction.data = incomingTransaction.result;
                incomingTransaction.result = undefined;
            } else {
                return
            }

            delete this.incomingTransactions[trCode];

            var response = await this.onEdgeReceivedCall(incomingTransaction.sessionId, incomingTransaction.data);
            if (response != undefined) {
                var trResponse = xchg.makeTransaction();
                trResponse.frameType = 0x11;
                trResponse.transactionId = incomingTransaction.transactionId;
                trResponse.sessionId = incomingTransaction.sessionId;
                trResponse.offset = 0;
                trResponse.totalSize = response.byteLength;
                trResponse.srcAddress = this.localAddress;
                trResponse.destAddress = incomingTransaction.srcAddress;
                trResponse.data = response;

                console.log("sending ...", trResponse);

                var offset = 0;
                var blockSize = 1024;
                while (offset < trResponse.data.byteLength) {
                    console.log("sending ...", offset);
                    var currentBlockSize = blockSize;
                    var restDataLen = trResponse.data.length - offset;
                    if (restDataLen < currentBlockSize) {
                        currentBlockSize = restDataLen;
                    }

                    var trBlock = xchg.makeTransaction();
                    trBlock.frameType = 0x11;
                    trBlock.transactionId = trResponse.transactionId;
                    trBlock.sessionId = trResponse.sessionId;
                    trBlock.offset = offset;
                    trBlock.totalSize = response.byteLength;
                    trBlock.srcAddress = trResponse.srcAddress;
                    trBlock.destAddress = trResponse.destAddress;
                    trBlock.data = trResponse.data.slice(offset, offset + currentBlockSize);

                    var responseFrameBlock = trBlock.serialize()
                    await this.sendFrame(trBlock.destAddress, responseFrameBlock);
                    offset += currentBlockSize;
                }
            }

        },
        processFrame11(t) {
            var remotePeer = this.remotePeers[t.srcAddress];
            if (remotePeer == undefined) {
                console.log("processFrame11 - peer not found", t.srcAddress, this.remotePeers)
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

            var publicKeyBS = await xchg.rsaExportPublicKey(this.keyPair.publicKey);
            //console.log(publicKeyBS);
            var signature = await xchg.rsaSign(nonceHash, this.keyPair.privateKey);
            console.log("signature:", signature);

            var response = new ArrayBuffer(16 + 512 + publicKeyBS.byteLength);
            xchg.copyBA(response, 0, nonce);
            xchg.copyBA(response, 16, signature);
            xchg.copyBA(response, 16 + 512, publicKeyBS);

            var trResponse = xchg.makeTransaction();
            trResponse.frameType = 0x21;
            trResponse.transactionId = 0;
            trResponse.sessionId = 0;
            trResponse.offset = 0;
            trResponse.totalSize = response.byteLength;
            trResponse.srcAddress = this.localAddress;
            trResponse.destAddress = t.srcAddress;
            trResponse.data = response;

            console.log("response 21", trResponse);
            var frResponse = trResponse.serialize();
            console.log("response 21 frame", frResponse);
            this.sendFrame(trResponse.destAddress, frResponse);
        },
        async processFrame21(t) {
            console.log("received 21", t);
            if (t.data.byteLength < 16 + 512) {
                return
            }

            var receivedNonce = t.data.slice(0, 16);

            var receivedPublicKeyBS = t.data.slice(16 + 512);
            var receivedPublicKey = await xchg.rsaImportPublicKey(receivedPublicKeyBS);
            var receivedAddress = await xchg.addressFromPublicKey(receivedPublicKey);
            var remotePeer = this.remotePeers[receivedAddress];
            if (remotePeer === undefined) {
                return
            }

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
            console.log("sendFrame", frame);
            var frame64 = xchg.arrayBufferToBase64(frame);
            const formData = new FormData();
            formData.append('d', frame64);
            const response = await axios.post("http://localhost:8084/api/w", formData, {
                headers: formData.headers
            },);
            console.log("sendFrame ok", frame);
        },

        async onEdgeReceivedCall(sessionId, data) {
            var encrypted = false;
            var session = undefined;
            if (sessionId != 0) {
                session = this.sessions[sessionId]
            }

            if (sessionId != 0) {
                if (session === undefined) {
                    throw "no session found";
                }

                data = await xchg.aesDecrypt(data, session.aesKey);
                data = await xchg.unpack(data);
                if (data.byteLength < 9) {
                    throw "wrong data len";
                }

                encrypted = true;
                var dataView = new DataView(data);
                var callNonce = dataView.getBigUint64(0, true);
                if (!session.snakeCounter.testAndDeclare(callNonce)) {
                    throw "session nonce error";
                }

                data = data.slice(8);
                session.lastAccessDT = Date.now();
            } else {
                if (data.byteLength < 1) {
                    throw "wrong frame len (1)";
                }
            }

            var dataView = new DataView(data);

            var funcLen = dataView.getUint8(0);
            if (data.byteLength < 1 + funcLen) {
                throw "wrong data frame len(fn)";
            }

            var funcNameBA = data.slice(1, 1 + funcLen);
            var funcName = new TextDecoder().decode(funcNameBA);
            var funcParameter = data.slice(1 + funcLen);

            console.log("funcName", funcName);

            var response = new ArrayBuffer(0);

            try {
                if (sessionId == 0) {
                    var processed = false;
                    if (funcName === "/xchg-get-nonce") {
                        response = await this.nonces.next();
                        processed = true;
                    }
                    if (funcName === "/xchg-auth") {
                        response = await this.processAuth(funcParameter);
                        processed = true;
                    }

                    if (!processed) {
                        throw "wrong func without session";
                    }
                } else {
                    response = await this.processFunction(funcName, funcParameter);
                }
                var responseFinal = new ArrayBuffer(1 + response.byteLength);
                var responseFinalView = new DataView(responseFinal);
                console.log(responseFinal);
                responseFinalView.setUint8(0, 0);
                xchg.copyBA(responseFinal, 1, response);
                response = responseFinal;
                console.log("SERVER SUCCESS");
            } catch (ex) {
                console.log("SERVER ERROR", ex);
                var errorBA = new TextEncoder().encode(ex.toString());
                response = new ArrayBuffer(1 + errorBA.byteLength);
                var responseView = new DataView(response);
                responseView.setUint8(0, 1);
                xchg.copyBA(response, 1, errorBA);
            }

            if (encrypted) {
                response = await xchg.pack(response);
                response = await xchg.aesEncrypt(response, session.aesKey);
            }

            return response;
        },

        async processFunction(funcName, funcParameter) {
            console.log("PROCESSING", funcName);
            return new TextEncoder().encode("RESULT OF FUNCTION").buffer;            
        },

        async processAuth(funcParameter) {
            if (funcParameter.byteLength < 4) {
                throw "processAuth: funcParameter.byteLength < 4";
            }

            var funcParameterView = new DataView(funcParameter);

            var remotePublicKeyBALen = funcParameterView.getUint32(0, true);
            if (funcParameter.byteLength < 4 + remotePublicKeyBALen) {
                throw "processAuth: funcParameter.byteLength < 4+remotePublicKeyBALen";
            }
            var remotePublicKeyBA = funcParameter.slice(4, 4 + remotePublicKeyBALen);
            var remotePublicKey = await xchg.rsaImportPublicKey(remotePublicKeyBA);

            var authFrameSecret = funcParameter.slice(4 + remotePublicKeyBALen);
            var parameter = await xchg.rsaDecrypt(authFrameSecret, this.keyPair.privateKey);
            console.log("parameter", parameter);
            if (parameter.byteLength < 16) {
                throw "processAuth: parameter.byteLength < 16";
            }
            var nonce = parameter.slice(0, 16);

            this.nonces.check(nonce);

            var authData = parameter.slice(16);
            // TODO: check authData

            var sessionId = this.nextSessionId;
            this.nextSessionId++;

            var session = makeSession();
            session.id = sessionId;
            session.lastAccessDT = Date.now();
            session.aesKey = new ArrayBuffer(32);
            var aesView = new DataView(session.aesKey);
            const randomArray = new Uint8Array(32);
            await crypto.getRandomValues(randomArray);
            for (var i = 0; i < 32; i++) {
                aesView.setUint8(i, randomArray[i]);
            }
            session.snakeCounter = xchg.makeSnakeCounter(100, 1);
            this.sessions[sessionId] = session;

            var response = new ArrayBuffer(8 + 32);
            var responseView = new DataView(response);
            responseView.setBigUint64(0, BigInt(sessionId), true);
            xchg.copyBA(response, 8, session.aesKey);
            response = await xchg.rsaEncrypt(response, remotePublicKey);
            return response;
        },

    };
}

function makeSession() {
    return {
        id: BigInt(0),
        aesKey: new ArrayBuffer(0),
        lastAccessDT: 0,
        snakeCounter: xchg.makeSnakeCounter(1000, 1),
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
        outgoingTransactions: {},
        authProcessing: false,
        start() {
            this.nonces = xchg.makeNonces(1000);
            this.timer = window.setInterval(this.backgroundWorker, 200, this);
        },
        stop() {
            window.clearInterval(this.timer)
        },
        backgroundWorker(ctx) {
        },
        async call(func, data) {
            if (this.remotePublicKey === undefined) {
                await this.requestPublicKey();
            }

            if (this.sessionId === 0) {
                await this.auth();
            }

            var result = await this.regularCall(func, data, this.aesKey);
            return result;
        },
        async requestPublicKey() {
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

            console.log("send 20", t);

            this.sendFrame(t.destAddress, frame);
        },

        async sendFrame(destAddress, frame) {
            var frame64 = xchg.arrayBufferToBase64(frame);
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
            // Waiting for previous auth process
            for (var i = 0; i < 100; i++) {
                if (!this.authProcessing) {
                    break;
                }
                await xchg.sleep(10);
            }

            if (this.authProcessing) {
                throw "auth is processing";
            }

            // Previous auth is SUCCESS
            if (this.aesKey !== undefined && this.aesKey.byteLength == 32 && this.sessionId !== 0) {
                return
            }

            // Encode auth data to ArrayBuffer
            var enc = new TextEncoder();
            this.authData = enc.encode("pass").buffer;

            try {
                this.authProcessing = true;

                // Waiting for public key
                for (var i = 0; i < 100; i++) {
                    if (this.remotePublicKey !== undefined) {
                        break;
                    }
                    await xchg.sleep(10);
                }

                // Cannot auth with unknown remote public key
                if (this.remotePublicKey === undefined) {
                    throw "no remote public key"
                }

                // Get a nonce from server to auth
                // The nonce is used to prevent replay attack
                var nonce = await this.regularCall("/xchg-get-nonce", new ArrayBuffer(0), new ArrayBuffer(0));

                if (nonce.byteLength != 16) {
                    throw "wrong nonce length";
                }

                // RSA-2048 public key as an ArrayBuffer
                var localPublicKeyBA = await xchg.rsaExportPublicKey(this.localKeys.publicKey);

                // This path will be encrypted with remote public key:
                // received nonce and secret auth data
                var authFrameSecret = new ArrayBuffer(16 + this.authData.byteLength);
                xchg.copyBA(authFrameSecret, 0, nonce);
                xchg.copyBA(authFrameSecret, 16, this.authData);

                // Encrypt secret data (nonce and auth data) with RSA-2048
                var encryptedAuthFrame = await xchg.rsaEncrypt(authFrameSecret, this.remotePublicKey);

                // Prepare final auth frame
                // [0:4] - length of local public key
                // [4:PK_LEN] - local public key
                // [PK_LEN:] - encrypted (RSA-2048) nonce and auth data
                var authFrame = new ArrayBuffer(4 + localPublicKeyBA.byteLength + encryptedAuthFrame.byteLength);
                var authFrameView = new DataView(authFrame);
                authFrameView.setUint32(0, localPublicKeyBA.byteLength, true);
                xchg.copyBA(authFrame, 4, localPublicKeyBA);
                xchg.copyBA(authFrame, 4 + localPublicKeyBA.byteLength, encryptedAuthFrame);

                // --------------------------------------------------
                // Call Auth
                var result = await this.regularCall("/xchg-auth", authFrame, new ArrayBuffer(0), new ArrayBuffer(0));
                // --------------------------------------------------

                if (this.localKeys === undefined) {
                    throw "auth: no local key";
                }

                // Response encrypted by local public key
                // Decrypt it
                result = await xchg.rsaDecrypt(result, this.localKeys.privateKey);
                if (result === undefined) {
                    throw "auth: result of rsaDecrypt is undefined";
                }

                // Result:
                // [0:8] - sessionId
                // [8:40] - aes key of the session
                if (result.byteLength != 8 + 32) {
                    throw "auth wrong response length";
                }

                // Get sessionId from the response
                var resultView = new DataView(result);
                this.sessionId = resultView.getBigUint64(0, true);

                // Get AES key of the session
                this.aesKey = result.slice(8);
            } catch (ex) {
                this.authProcessing = false;
                throw ex;
            } finally {
                this.authProcessing = false;
            }

            return true;
        },

        async regularCall(func, data, aesKey) {
            // Prepare function name
            var enc = new TextEncoder();
            var funcBS = enc.encode(func);
            funcBS = funcBS.buffer;
            if (funcBS.byteLength > 255) {
                throw "regularCall: func length > 255";
            }

            var encrypted = false;

            // Check local RSA keys
            if (this.localKeys === undefined) {
                throw "localKeys === undefined";
            }

            // Session nonce counter must be incremented everytime
            var sessionNonceCounter = this.sessionNonceCounter;
            this.sessionNonceCounter++;

            // Prepare frame
            var frame = new ArrayBuffer(0);
            if (aesKey !== undefined && aesKey.byteLength == 32) {
                // Session is active
                // Using AES encryption with ZIP
                frame = new ArrayBuffer(8 + 1 + funcBS.byteLength + data.byteLength);
                var frameView = new DataView(frame);
                frameView.setBigUint64(0, BigInt(sessionNonceCounter), true);
                frameView.setUint8(8, funcBS.byteLength);
                xchg.copyBA(frame, 9, funcBS);
                xchg.copyBA(frame, 9 + funcBS.byteLength, data);
                frame = await xchg.pack(frame);
                frame = await xchg.aesEncrypt(frame, aesKey);
                encrypted = true;
            } else {
                // Session is not active
                // Encryption is not used
                frame = new ArrayBuffer(1 + funcBS.byteLength + data.byteLength);
                var frameView = new DataView(frame);
                frameView.setUint8(0, funcBS.byteLength);
                xchg.copyBA(frame, 1, funcBS);
                xchg.copyBA(frame, 1 + funcBS.byteLength, data);
            }

            // Executing transaction with response waiting
            var result = await this.executeTransaction(this.sessionId, frame);

            if (encrypted) {
                // Request was encrypted with AES
                // Expect encrypted response
                result = await xchg.aesDecrypt(result, aesKey);
                // UnZIP
                result = await xchg.unpack(result);
            }

            // Minimum size of response is 1 byte
            if (result.byteLength < 1) {
                throw "result.byteLength < 1";
            }

            var resultData = new ArrayBuffer(0);
            var resultView = new DataView(result);
            if (resultView.getUint8(0) == 0) {
                // Success
                resultData = new ArrayBuffer(result.byteLength - 1);
                xchg.copyBA(resultData, 0, result, 1);
            }

            if (resultView.getUint8(0) == 1) {
                console.log("ERROR BIT: ", result);
                resultData = new ArrayBuffer(result.byteLength - 1);
                xchg.copyBA(resultData, 0, result, 1);
                var dec = new TextDecoder();
                throw dec.decode(resultData);
            }

            return resultData;
        },

        async processFrame11(transaction) {
            var t = this.outgoingTransactions[transaction.transactionId];
            if (t === undefined) {
                console.log("transaction not found", transaction.transactionId, this.outgoingTransactions);
                return
            }

            if (transaction.err === undefined && transaction.totalSize < 1024 * 1024) {
                t.appendReceivedData(transaction);
            } else {
                t.result = new ArrayBuffer(0);
                t.err = transaction.err;
                t.complete = true;
            }
        },

        async executeTransaction(sessionId, data) {
            var transactionId = this.nextTransactionId;
            this.nextTransactionId++;

            var t = xchg.makeTransaction();
            t.frameType = 0x10;
            t.transactionId = transactionId;
            t.sessionId = sessionId;
            t.offset = 0;
            t.totalSize = data.byteLength;
            t.data = data;
            t.srcAddress = this.localAddress;
            t.destAddress = this.remoteAddress;

            this.outgoingTransactions[transactionId] = t;

            var offset = 0;
            var blockSize = 1024;
            while (offset < data.byteLength) {
                var currentBlockSize = blockSize;
                var restDataLen = data.byteLength - offset;
                if (restDataLen < currentBlockSize) {
                    currentBlockSize = restDataLen;
                }

                var tBlock = xchg.makeTransaction();
                tBlock.frameType = 0x10;
                tBlock.transactionId = transactionId;
                tBlock.sessionId = sessionId;
                tBlock.offset = offset;
                tBlock.totalSize = data.byteLength;
                tBlock.data = data.slice(offset, offset + currentBlockSize);
                tBlock.srcAddress = this.localAddress;
                tBlock.destAddress = this.remoteAddress;
                var tBlockBA = tBlock.serialize();

                console.log("send remote peer", tBlock);
                await this.sendFrame(t.destAddress, tBlockBA);
                offset += currentBlockSize;
            }

            for (var i = 0; i < 100; i++) {
                if (t.complete) {
                    delete this.outgoingTransactions[transactionId];
                    if (t.err !== undefined) {
                        throw t.err
                    }

                    return t.result;
                }
                await xchg.sleep(10);
            }

            throw "transaction timeout";

        },
    };
}
