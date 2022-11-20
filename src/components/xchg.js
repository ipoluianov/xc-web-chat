var xchg = new makeXchg();
export default xchg;

import axios from "axios";
import JSZip from "jszip";

function makeXchg() {
    return {
        base64ToArrayBuffer(base64string) {
            var binary_string = window.atob(base64string);
            var len = binary_string.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        },

        binaryStringToArrayBuffer(binaryString) {
            var len = binaryString.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        },

        arrayBufferToBase64(buffer) {
            var binary = "";
            var bytes = new Uint8Array(buffer);
            var len = bytes.byteLength;
            for (var i = 0; i < len; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
        },


        arrayBufferToBinaryString(arrayBuffer) {
            var binaryString = "";
            var bytes = new Uint8Array(arrayBuffer);
            var len = bytes.byteLength;
            for (var i = 0; i < len; i++) {
                binaryString += String.fromCharCode(bytes[i]);
            }
            return binaryString;
        },

        async addressFromPublicKey(publicKey) {
            var publicKeyBS = await this.rsaExportPublicKey(publicKey);
            var publicKeyBSHash = await crypto.subtle.digest('SHA-256', publicKeyBS);
            var addressBS = publicKeyBSHash.slice(0, 30);
            return this.addressBSToAddress32(addressBS);
        },

        addressToAddressBS(address) {
            var addressBS = xchg.decode32(address)
            return this.binaryStringToArrayBuffer(addressBS);
        },

        addressBSToAddress32(addressBS) {
            var address32 = xchg.encode32(this.arrayBufferToBinaryString(addressBS))
            return "#" + address32.toLowerCase();
        },

        address32ToAddressBS(address32) {
            if (address32 === undefined) {
                return new ArrayBuffer(30);
            }
            address32 = address32.replaceAll("#", "")
            var addressBinaryString = xchg.decode32(address32)
            return this.binaryStringToArrayBuffer(addressBinaryString);
        },

        async rsaEncrypt(arrayBufferToEncrypt, publicKey) {
            var res = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                publicKey,
                arrayBufferToEncrypt
            );
            return res;
        },

        async rsaDecrypt(arrayBufferEncrypted, privateKey) {
            var res = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                arrayBufferEncrypted
            );
            return res;
        },

        async rsaSign(arrayBufferEncrypted, privateKey, publicKey) {
            var exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);
            var privateKeyForSigning = await window.crypto.subtle.importKey(
                "pkcs8",
                exportedPrivateKey,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256",
                },
                true,
                ["sign"]
            );


            var res = await window.crypto.subtle.sign(
                {
                    name: "RSA-PSS",
                    saltLength: 32,
                },
                privateKeyForSigning,
                arrayBufferEncrypted
            );

            return res;
        },

        async rsaVerify(dataToVerify, signature, publicKey) {
            var exportedPublicKey = await window.crypto.subtle.exportKey("spki", publicKey);
            var publicKeyForVerify = await window.crypto.subtle.importKey(
                "spki",
                exportedPublicKey,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256",
                },
                true,
                ["verify"]
            );

            console.log("Verify", publicKeyForVerify, signature, dataToVerify)

            var res = await window.crypto.subtle.verify(
                {
                    name: "RSA-PSS",
                    saltLength: 32,
                },
                publicKeyForVerify,
                signature,
                dataToVerify,
            );

            console.log("VERIFY", res);

            return res;
        },

        async aesEncrypt(arrayBufferToEncrypt, aesKey) {

            var aesKeyNative = await window.crypto.subtle.importKey("raw", aesKey,
                {
                    name: "AES-GCM",
                },
                true,
                ["encrypt", "decrypt"]);

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            var res = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    length: 256,
                    iv: iv,
                },
                aesKeyNative,
                arrayBufferToEncrypt
            );

            var vRes = new DataView(res);

            var result = new ArrayBuffer(iv.length + vRes.buffer.byteLength);

            var v = new DataView(result);
            for (var i = 0; i < iv.length; i++) {
                v.setUint8(i, iv.at(i))
            }
            for (var i = 0; i < vRes.buffer.byteLength; i++) {
                v.setUint8(i + iv.length, vRes.getUint8(i))
            }

            return result;
        },

        async aesDecrypt(arrayBufferEncrypted, aesKey) {
            var aesKeyNative = await window.crypto.subtle.importKey("raw", aesKey,
                {
                    name: "AES-GCM",
                },
                true,
                ["encrypt", "decrypt"]);


            var bs = new Uint8Array(arrayBufferEncrypted);
            var iv = bs.subarray(0, 12);
            var ch = bs.subarray(12);
            var res = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    length: 256,
                    iv: iv,
                },
                aesKeyNative,
                ch
            );
            return res;
        },

        async rsaExportPublicKey(publicKey) {
            var exportedPublicKey = await window.crypto.subtle.exportKey("spki", publicKey);
            return exportedPublicKey;
        },

        async rsaImportPublicKey(publicKeyBA) {
            var publicKey = await window.crypto.subtle.importKey("spki",
                publicKeyBA,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                true,
                ["encrypt"]
            );
            return publicKey;
        },

        async generateRSAKeyPair() {
            var keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );
            return keyPair;
        },
        async generateAESKey() {
            let keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "AES-GCM",
                    length: 256,
                },
                true,
                ["encrypt", "decrypt"]
            );
            return keyPair;
        },

        async pack(baData) {
            const zip = new JSZip();
            zip.file("data", baData);
            var content = await zip.generateAsync({ type: "arrayBuffer" });
            return content
        },

        async unpack(baZIP) {
            //var baZIP = this.base64ToArrayBuffer(zip64);
            var zip = await JSZip.loadAsync(baZIP);
            var content = await zip.files["data"].async('arrayBuffer')
            return content;
        },

        makeTransaction() {
            var t = {
                length: 0,
                crc: 0,
                frameType: 0,
                transactionId: 0n,
                sessionId: 0n,
                offset: 0,
                totalSize: 0,
                srcAddress: "",
                destAddress: "",
                data: new ArrayBuffer(0),

                receivedFrames: [],

                serialize() {
                    var result = new ArrayBuffer(128 + this.data.byteLength);
                    var view = new DataView(result);
                    view.setUint32(0, 128 + this.data.byteLength, true);
                    view.setUint8(8, this.frameType);
                    view.setBigUint64(16, BigInt(this.transactionId), true);
                    view.setBigUint64(24, BigInt(this.sessionId), true);
                    view.setUint32(32, this.offset, true);
                    view.setUint32(36, this.totalSize, true);
                    var srcAddressBS = xchg.address32ToAddressBS(this.srcAddress)
                    var srcAddressBSView = new DataView(srcAddressBS);
                    for (var i = 0; i < srcAddressBS.byteLength; i++) {
                        view.setUint8(40 + i, srcAddressBSView.getUint8(i));
                    }
                    var destAddressBS = xchg.address32ToAddressBS(this.destAddress)
                    var destAddressBSView = new DataView(destAddressBS);
                    for (var i = 0; i < destAddressBS.byteLength; i++) {
                        view.setUint8(70 + i, destAddressBSView.getUint8(i));
                    }

                    var dataView = new DataView(this.data);
                    for (var i = 0; i < this.data.byteLength; i++) {
                        view.setUint8(128 + i, dataView.getUint8(i));
                    }
                    return result;
                },

                appendReceivedData(transaction) {
                    if (this.receivedFrames.length < 1000) {
                        var found = false;
                        for (var i = 0; i < this.receivedFrames.length; i++) {
                            var tr = this.receivedFrames[i];
                            if (tr.offset == transaction.offset) {
                                found = true;
                                break;
                            }
                        }

                        if (!found) {
                            this.receivedFrames.push(transaction);
                        }
                    }

                    var receivedDataLen = 0;
                    for (var i = 0; i < this.receivedFrames.length; i++) {
                        var tr = this.receivedFrames[i];
                        receivedDataLen += tr.data.byteLength;
                    }

                    if (receivedDataLen == transaction.totalSize) {
                        this.result = new ArrayBuffer(transaction.totalSize);
                        for (var i = 0; i < this.receivedFrames.length; i++) {
                            var tr = this.receivedFrames[i];
                            xchg.copyBA(this.result, tr.offset, tr.data);
                        }
                        //console.log("this.complete = true;");
                        this.complete = true;
                    }
                }
            }
            return t
        },

        makeNonces(count) {
            var ns = new ArrayBuffer(count * 16);
            return {
                nonces: ns,
                noncesCount: count,
                currentIndex: 0,
                complexity: 0,
                async fillNonce(index) {
                    if (index >= 0 && index < this.noncesCount) {
                        var view = new DataView(this.nonces);
                        view.setUint32(index * 16, index, true);
                        view.setUint8(index * 16 + 4, this.complexity);
                        const randomArray = new Uint8Array(11);
                        await crypto.getRandomValues(randomArray);
                        for (var i = 0; i < 11; i++) {
                            view.setUint8(5 + i, randomArray[i]);
                        }
                    }
                },
                async next() {
                    await this.fillNonce(this.currentIndex);
                    var result = new ArrayBuffer(16);
                    var resultView = new DataView(result);
                    var view = new DataView(this.nonces);
                    for (var i = 0; i < 16; i++) {
                        resultView.setUint8(i, view.getUint8(this.currentIndex * 16 + i), true);
                    }
                    this.currentIndex++;
                    if (this.currentIndex >= this.noncesCount) {
                        this.currentIndex = 0;
                    }
                    return result;
                },
                check(nonce) {
                    if (nonce.byteLength != 16) {
                        return false;
                    }
                    var view = new DataView(nonce);
                    var index = view.getUint32(0, true);
                    if (index < 0 || index >= this.noncesCount) {
                        return false;
                    }

                    var viewNonces = new DataView(this.nonces);

                    for (var i = 0; i < 16; i++) {
                        if (view.getUint8(i) != viewNonces.getUint8(index * 16 + i)) {
                            return false;
                        }
                    }

                    return true;
                },
            };
        },

        copyBA(destBA, destOffset, srcBA, srcOffsetBegin, srcOffsetEnd) {
            if (srcOffsetBegin === undefined) {
                srcOffsetBegin = 0;
            }
            if (srcOffsetEnd === undefined) {
                srcOffsetEnd = srcBA.byteLength;
            }
            var destView = new DataView(destBA);
            var srcView = new DataView(srcBA);
            var size = srcOffsetEnd - srcOffsetBegin;
            for (var i = 0; i < size; i++) {
                var srcOffset = srcOffsetBegin + i;
                var targetOffset = destOffset + i;
                if (targetOffset >= 0 && targetOffset < destBA.byteLength) {
                    destView.setUint8(targetOffset, srcView.getUint8(srcOffset));
                }
            }
        },

        makeSnakeCounter(size, initValue) {
            var initData = new ArrayBuffer(size);
            var initDataView = new DataView(initData);
            for (var i = 0; i < size; i++) {
                initDataView.setUint8(i, 1);
            }
            var result = {
                size: size,
                lastProcessed: BigInt(-1),
                data: initData,
                testAndDeclare(counter) {
                    counter = BigInt(counter)
                    if (counter < (this.lastProcessed - BigInt(this.size))) {
                        return false;
                    }

                    if (counter > this.lastProcessed) {
                        var shiftRange = counter - this.lastProcessed;
                        var dataView = new DataView(this.data);
                        var newData = new ArrayBuffer(this.size);
                        var newDataView = new DataView(newData);
                        for (var i = 0; i < this.size; i++) {
                            var b = 0;
                            var oldAddressOfCell = BigInt(i) - shiftRange;
                            if (oldAddressOfCell >= 0 && oldAddressOfCell < this.size) {
                                b = dataView.getUint8(Number(oldAddressOfCell));
                            }
                            newDataView.setUint8(i, b);
                        }
                        this.data = newData;
                        var dataViewN = new DataView(this.data);
                        dataViewN.setUint8(0, 1);
                        this.lastProcessed = counter;
                        return true;
                    }

                    var index = this.lastProcessed - counter;
                    if (index >= 0 && index < this.size) {
                        var dataView = new DataView(this.data);
                        if (dataView.getUint8(Number(index)) == 0) {
                            dataView.setUint8(this.lastProcessed - counter, 1);
                            return true;
                        }
                    }

                    return false;
                },
            };

            result.testAndDeclare(initValue);
            return result;
        },
        base32a: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        base32pad: "=",
        encode32(s) {
            var a = this.base32a;
            var pad = this.base32pad;
            var len = s.length;
            var o = "";
            var w, c, r = 0, sh = 0; // word, character, remainder, shift
            for (var i = 0; i < len; i += 5) {
                // mask top 5 bits
                c = s.charCodeAt(i);
                w = 0xf8 & c;
                o += a.charAt(w >> 3);
                r = 0x07 & c;
                sh = 2;

                if ((i + 1) < len) {
                    c = s.charCodeAt(i + 1);
                    // mask top 2 bits
                    w = 0xc0 & c;
                    o += a.charAt((r << 2) + (w >> 6));
                    o += a.charAt((0x3e & c) >> 1);
                    r = c & 0x01;
                    sh = 4;
                }

                if ((i + 2) < len) {
                    c = s.charCodeAt(i + 2);
                    // mask top 4 bits
                    w = 0xf0 & c;
                    o += a.charAt((r << 4) + (w >> 4));
                    r = 0x0f & c;
                    sh = 1;
                }

                if ((i + 3) < len) {
                    c = s.charCodeAt(i + 3);
                    // mask top 1 bit
                    w = 0x80 & c;
                    o += a.charAt((r << 1) + (w >> 7));
                    o += a.charAt((0x7c & c) >> 2);
                    r = 0x03 & c;
                    sh = 3;
                }

                if ((i + 4) < len) {
                    c = s.charCodeAt(i + 4);
                    // mask top 3 bits
                    w = 0xe0 & c;
                    o += a.charAt((r << 3) + (w >> 5));
                    o += a.charAt(0x1f & c);
                    r = 0;
                    sh = 0;
                }
            }
            // Encode the final character.
            if (sh != 0) { o += a.charAt(r << sh); }
            // Calculate length of pad by getting the 
            // number of words to reach an 8th octet.
            var padlen = 8 - (o.length % 8);
            // modulus 
            if (padlen == 8) { return o; }
            if (padlen == 1) { return o + pad; }
            if (padlen == 3) { return o + pad + pad + pad; }
            if (padlen == 4) { return o + pad + pad + pad + pad; }
            if (padlen == 6) { return o + pad + pad + pad + pad + pad + pad; }
            console.log('there was some kind of error');
            console.log('padlen:' + padlen + ' ,r:' + r + ' ,sh:' + sh + ', w:' + w);
        },
        decode32(s) {
            var len = s.length;
            var apad = this.base32a + this.base32pad;
            var v, x, r = 0, bits = 0, c, o = '';

            s = s.toUpperCase();

            for (var i = 0; i < len; i += 1) {
                v = apad.indexOf(s.charAt(i));
                if (v >= 0 && v < 32) {
                    x = (x << 5) | v;
                    bits += 5;
                    if (bits >= 8) {
                        c = (x >> (bits - 8)) & 0xff;
                        o = o + String.fromCharCode(c);
                        bits -= 8;
                    }
                }
            }
            // remaining bits are < 8
            if (bits > 0) {
                c = ((x << (8 - bits)) & 0xff) >> (8 - bits);
                // Don't append a null terminator.
                // See the comment at the top about why this sucks.
                if (c !== 0) {
                    o = o + String.fromCharCode(c);
                }
            }
            return o;
        },

        async getNodesByAddress(address) {
            var result = [];

            if (address == undefined) {
                return [];
            }

            var network = await xchg.makeNetwork();
            network = JSON.parse(network)
            console.log("Network", network);

            address = address.replaceAll("#", "").toLowerCase();
            var addressBA = new TextEncoder().encode(address);
            var addressBAHash = await crypto.subtle.digest('SHA-256', addressBA);
            var addressBAHashHex = xchg.buf2hex(addressBAHash);

            var preferredRange = undefined
            var preferredRangeScores = 0

            for (var i = 0; i < network.ranges.length && i < addressBAHashHex.length; i++) {
                var range = network.ranges[i];
                //console.log("range", range);
                var rangeScores = 0;
                for (var cIndex = 0; cIndex < range.prefix.length; cIndex++) {
                    var chInRange = range.prefix[cIndex];
                    var chInAddressBAHashHex = addressBAHashHex[cIndex];
                    if (chInRange == chInAddressBAHashHex) {
                        rangeScores++;
                    }
                }

                if (rangeScores == range.prefix.length && rangeScores > preferredRangeScores) {
                    preferredRange = range;
                    preferredRangeScores = rangeScores;
                }
            }

            if (preferredRange !== undefined) {
                for (var i = 0; i < preferredRange.hosts.length; i++) {
                    result.push(preferredRange.hosts[i].address);
                }
            }

            return result;
        },

        buf2hex(buffer) {
            return [...new Uint8Array(buffer)]
                .map(x => x.toString(16).padStart(2, '0'))
                .join('');
        },

        makeXPeer() {
            return {
                keyPair: {},
                remotePeers: {},
                incomingTransactions: {},
                localAddress: "",
                nonces: {},
                sessions: {},
                nextSessionId: 1,
                routers: {},
                async start() {
                    this.keyPair = await xchg.generateRSAKeyPair();
                    this.localAddress = await xchg.addressFromPublicKey(this.keyPair.publicKey);
                    console.log("start local address:", this.localAddress);
                    this.timer = window.setInterval(this.backgroundWorker, 100, this);
                    this.nonces = xchg.makeNonces(1000);

                    var nodes = await xchg.getNodesByAddress("#3xk6hf4jegiurclldhl74ddf2pqhrsozr5lvhavs6phr4uku");

                    for (var i = 0; i < nodes.length; i++) {
                        var addr = nodes[i];
                        var peerHttp = xchg.makePeerHttp(addr, this, this.localAddress);
                        this.routers[addr] = peerHttp;
                        peerHttp.start();
                    }
                },
                async stop() {
                    window.clearInterval(this.timer)
                },
                backgroundWorker(ctx) {
                    ctx.purgeSessions();
                },
                async call(address, authData, func, data) {
                    if (address.length != 49) {
                        throw "wrong address";
                    }

                    console.log("***************authData", authData);

                    var remotePeer
                    if (this.remotePeers[address] != undefined) {
                        remotePeer = this.remotePeers[address];
                    } else {
                        remotePeer = xchg.makeRemotePeer(this.localAddress, address, authData, this.keyPair);
                        remotePeer.start();
                        this.remotePeers[address] = remotePeer;
                    }
                    remotePeer.authData = authData;
                    return await remotePeer.call(func, data);
                },

                lastPurgeSessionsDT: 0,
                async purgeSessions() {
                    var now = Date.now();
                    if (now - this.lastPurgeSessionsDT > 5 * 60 * 1000) {
                        var found = true;
                        while (found) {
                            found = false;
                            for (const [key, value] of Object.entries(this.sessions)) {
                                if (now - value.lastAccessDT > 1000) {
                                    console.log("remote session", key);
                                    delete this.sessions[key];
                                    found = true;
                                    break;
                                }
                            }
                        }
                        this.lastPurgeSessionsDT = now;
                    }
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
                        //console.log("processFrame exception", ex);
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

                        var offset = 0;
                        var blockSize = 1024;
                        while (offset < trResponse.data.byteLength) {
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
                    var addressStringBytes = t.data.slice(16);
                    var address = new TextDecoder().decode(addressStringBytes);
                    if (address !== this.localAddress) {
                        return
                    }

                    var publicKeyBS = await xchg.rsaExportPublicKey(this.keyPair.publicKey);
                    var signature = await xchg.rsaSign(nonce, this.keyPair.privateKey, this.keyPair.publicKey);

                    var response = new ArrayBuffer(16 + 256 + publicKeyBS.byteLength);
                    xchg.copyBA(response, 0, nonce);
                    xchg.copyBA(response, 16, signature);
                    xchg.copyBA(response, 16 + 256, publicKeyBS);

                    var trResponse = xchg.makeTransaction();
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
                    // [0:16] - original nonce
                    // [16:16+256] - signature of SHA256(nonce)
                    // [16+256:] - remote public key
                    if (t.data.byteLength < 16 + 256) {
                        return
                    }

                    var receivedNonce = t.data.slice(0, 16);
                    var receivedPublicKeyBS = t.data.slice(16 + 256);
                    var receivedPublicKey = {}
                    try {
                        receivedPublicKey = await xchg.rsaImportPublicKey(receivedPublicKeyBS);
                    }
                    catch (ex) {
                        throw "cannot import remote public key";
                    }
                    var receivedAddress = await xchg.addressFromPublicKey(receivedPublicKey);
                    var remotePeer = this.remotePeers[receivedAddress];
                    if (remotePeer === undefined) {
                        return
                    }

                    var nonceHash = await crypto.subtle.digest('SHA-256', receivedNonce);
                    var signature = t.data.slice(16, 16 + 256);
                    var verifyRes = await xchg.rsaVerify(receivedNonce, signature, receivedPublicKey);
                    if (verifyRes !== true) {
                        console.log("verifyRes", verifyRes);
                        throw "signature verify error";
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

                async sendFrameToRouter(node, formData) {
                    try {
                        await axios.post("http://" + node + "/api/w", formData, {
                            headers: formData.headers
                        },);
                    } catch (ex) {
                        console.log("send exception: ", ex);
                    }
                },

                async sendFrame(destAddress, frame) {
                    var frame64 = xchg.arrayBufferToBase64(frame);
                    const formData = new FormData();
                    formData.append('d', frame64);
                    var nodes = await xchg.getNodesByAddress(destAddress);
                    for (var i = 0; i < nodes.length; i++) {
                        var node = nodes[i];
                        this.sendFrameToRouter(node, formData);
                    }
                },

                async onEdgeReceivedCall(sessionId, data) {
                    var encrypted = false;
                    var session = undefined;
                    if (sessionId != 0) {
                        session = this.sessions[sessionId]
                    }

                    if (sessionId != 0) {
                        if (session === undefined) {
                            throw "{XCHG_ERR_NO_SESSSION_FOUND}";
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
                        responseFinalView.setUint8(0, 0);
                        xchg.copyBA(responseFinal, 1, response);
                        response = responseFinal;
                    } catch (ex) {
                        console.log("SERVER ERROR", ex);
                        response = this.prepareErrorFrame(ex.toString());
                    }

                    if (encrypted) {
                        response = await xchg.pack(response);
                        response = await xchg.aesEncrypt(response, session.aesKey);
                    }

                    return response;
                },

                async prepareErrorFrame(errorString) {
                    var errorBA = new TextEncoder().encode(errorString).buffer;
                    var response = new ArrayBuffer(1 + errorBA.byteLength);
                    var responseView = new DataView(response);
                    responseView.setUint8(0, 1);
                    xchg.copyBA(response, 1, errorBA);
                    return response;
                },

                async processFunction(funcName, funcParameter) {
                    return new TextEncoder().encode(Date.now().toString()).buffer;
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
                    if (parameter.byteLength < 16) {
                        throw "processAuth: parameter.byteLength < 16";
                    }
                    var nonce = parameter.slice(0, 16);

                    this.nonces.check(nonce);

                    var authData = parameter.slice(16);
                    if (this.onAuth !== undefined) {
                        this.onAuth(authData);
                    } else {
                        throw "processAuth: no auth function";
                    }

                    var sessionId = this.nextSessionId;
                    this.nextSessionId++;

                    var session = xchg.makeSession();
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
        },

        makeSession() {
            return {
                id: BigInt(0),
                aesKey: new ArrayBuffer(0),
                lastAccessDT: 0,
                snakeCounter: xchg.makeSnakeCounter(1000, 1),
            };
        },

        NetworkContainerDefault: "UEsDBBQACAAIADWLdFUAAAAAAAAAAAAAAAAMAAkAbmV0d29yay5qc29uVVQFAAEGVXpj1NBBbqswEAbgvU8xmnXkBEIc4A7vXaBClQMTsAo2Mq6KEuXulVNaqVGlsJ2NF+Nfv76ZqwC0eiAsAf9pY/9TwI0ADGagKehhxBISpfJCJYcsjT/GmmB0/zo6Y8OEJbwIAOxCGMvtdq67dpaWwtZS+HD+TV7MKE96IpXF3l9B2eoLeVn37r15ltd9TzXJ2g0rkysMS9L59q+kgCqu67Vt6XvNqwAAHD2dzRwvtrv3AXZu+jnFkgJA3TSepjjHQyb3R3ncy0TtynyXf0Fi6PH49/Ft87QoTYs1RfGtxNL4yE9481Pe/D1vfsabf+DNV7z5R978nDe/4M3XvPkn3vyaN7/hzSfe/DMfvoBK3D4DAAD//1BLBwhlUgJHEgEAAB8NAABQSwMEFAAIAAgANYt0VQAAAAAAAAAAAAAAABAACQBzaWduYXR1cmUuYmFzZTY0VVQFAAEGVXpjBMC5YoIwAADQD3IQtRwZOpQiigiBkEPckDQiCfepX99nuIzPH/n3m4tLX6Q+CEXoEZ5n5krHxPCMMGg1rdINDYP0bk3EDRaYwyz+2qyH7aaBq05jPSKbL4zJJhC8/TxAqenIKqx17GYRLQ4RwgLEHsemOuK7HaC1nvwnQ9ihGPw5rxxdpIqdM5c/2+hj8u2yC4L5wIaMUV8/LUkamQenaK8t6HZSS0169DJ0O1fuYncXrin9RftQm9NwJS7sVcYqiSvmJz8wM492vIP1VdgKLV3BKbxJte0eahHesC+oFacP62hYDodEINOt97u3o/ryagPRdjWL6qj8fV9t5u9lM8kpU/3A/BqO1fN98nJx8pvb9ByCi3tOwClBJVF3HH9//wcAAP//UEsHCNxX1PkmAQAAWAEAAFBLAQIUABQACAAIADWLdFVlUgJHEgEAAB8NAAAMAAkAAAAAAAAAAAAAAAAAAABuZXR3b3JrLmpzb25VVAUAAQZVemNQSwECFAAUAAgACAA1i3RV3FfU+SYBAABYAQAAEAAJAAAAAAAAAAAAAABVAQAAc2lnbmF0dXJlLmJhc2U2NFVUBQABBlV6Y1BLBQYAAAAAAgACAIoAAADCAgAAAAA=",
        NetworkContainerEncryptedPrivateKey: "uTC09uvV2vNvwes9yj+bb80UbQh14JSFG22MSMFYgd6odNyqRw9jluBfWg4ZE38k/rugSyvchj23DN54QM3lQxuiqe35YaSvkdAsNxumOaSvsXbezY4iz/WljSfqMjKVPHtUl81RusgNZAAegp8XL7u8UBFREPSQGqhqQGggDcnp8qtXz13yo3NVFJ1Zq+kkfWT2EJyhhi+u3LIpPE4s8I/ht9LERqYeGsXbWBxCwHWHa9MWHIsa6B2naL1VEEUdpQ1GvHNY62FWFMcjpUbXNJwNDEo2GUYXYv3cbj/HFrEebhglB6FomyjkHXWEPQf7CVZx3TVjZfmCTBL5f6ud/5MOvPX2aAbeVtvLw5fT5ZocnPExAMoFlYmwfSZWRauGFAavV7FLHvtkdGDQn33Z1adkL/Bgnz68ijR9SjA+XfQn7d2OTYIgN9FhhN1m8a4wovx4geRxFxJhe0kUVDHt+gXFPavBAcNb/iGu10CDk23WkFaN+eVTRP7WKviVhUsiraTW0CsGr1E0HYy6SY0A6PbEgWEP2azg8jAZRKiYG0uLyy81JN9C55oSAXcNKooqblcX4bPB9tI1cy4zbdhj6GehfxRQ872ZsGwnpDzy3iiQstI7XYhUvQKctl7IPz4JN++sP1qUvkFaUfEeXFtzzgZ5d92qsaMqz+6yA5kFk792I+W3F/mJdQnqeLhNKN3e+PWj2UlPpjFOmcCg6d/pKHCZk6GWYHU/V37/rLYkI6uw63r6/xMmpukXcbYvH5yd/5Ej0ohrtwz3iR5ZzpXVBIOlapW50lvYoBPLpPFtIKCPj3GMp8jqut9OsiYqCCmOdTKa49regsyJtomVhU+o26i8EHrvgGqQdHhFgDY2XlUB6C/KgKuYuML/8DzTyc+0qxnxeVMwC5Ug+H8qaBJMBlj0p1TDnGIKU2B/fostvL980a6pu9OUhgbCkEvQk8ba6KbDIsVjsVV2bAGi2sx4Gsr5z6x8O0taW+pO2ZE8gjq4WNiF9iWvG4JPclux0NbNhz3CPmfxhC80is25r6KbYHm8UhCTmsa7scWxV60pArpJyyoFf65L4kvxrmEKHAvUQYXs02wQ3e/mqaJuIzkfPkJFqB0R8y68nFLf3XKZQNaBT6QKaMEBfg0/CSkHCPZMRJMu+Rn85w1n4dB+J5mRKo/0cSk+3zGbQR+NbjgNIMUb/pUkJwrKhEJppejRBuu9Yvolu+q/2rnbBEElz/OrOyqw2vP9bbv0Q0HB2JkYD97j8aPbg8Vw6SOfaoyGzbJ21LNNlfPAWF4skyi8RvEAXGRnGS/zRDkTSUqANK+unAMgRTxEFgK2b86BMQuCxm6kPAW0GdY0nqkGvrdTK6Gs+8aLSI21dPHN/n2OCoIZvOqu3l9v6mlHtONJqbvfsDFk64hztO2p0SdhVi84I19y/hMJQESkKorGVR5XH/mKCBcBanYtpKhOtQZdWNT9taImL9EKtTeXcOfjs8YPSCGunueYp+nDBSmhlrC/K1mVCBAaUXVTxe1YaVGrXRMlIYUIB2g+KkV0d7ZNxzhqNJcw1Aud322IXI9aB4c8HismCRUp7NkRmTPYlT/hBJUJ1hVCIYWvzNYXd2Cse6bksv8KSpYf1rJHszGlvlHD4T8VBs29i0XDb5UyGLmLeyYRGz4=",
        NetworkContainerPublicKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8V7FEvpzVo4sLhE3rIEmKwbLmNZkweZLucv/vxIbj3y8jpJiEGT3kQA9JvGscdsS85gca34WCfKdMJBKErUm28/UAWnDZeVUmQyxwGXs2jO/OLQukwJT76Umsu/KIfr7zKxkzfm7fTsJ8q1ZYuHgndi4OTblKqy/tSynyEYFnlbpEvmIAS2ZJblarxaG5VJo3YA5ZdO5FTcuaSkZ+9v4uMvcwFK9qIigJCS+xJa+ubgN9cv2RuHuQB7+Qw9bGbCjk9cSGnbV0ttwoVMZxFkT72lAXdp5/NLWcRpKnnjEvkWKjo21ROeH6hk4qfa30Q/Q+hLbPxhLlXX2r9sNEEZkWQIDAQAB",
        NetworkContainerFileNetwork: "network.json",
        NetworkContainerFileSignature: "signature.base64",

        async loadNetworkFromZip64(zip64) {
            var zipBA = xchg.base64ToArrayBuffer(zip64)
            var publicKeyBA = this.base64ToArrayBuffer(this.NetworkContainerPublicKey)
            var publicKey = await this.rsaImportPublicKey(publicKeyBA)
            var zip = await JSZip.loadAsync(zipBA);
            var contentNetwork = await zip.files[this.NetworkContainerFileNetwork].async('arrayBuffer')
            var contentSignature = await zip.files[this.NetworkContainerFileSignature].async('arrayBuffer')

            contentSignature = new TextDecoder().decode(contentSignature)
            contentSignature = xchg.base64ToArrayBuffer(contentSignature)

            //contentNetwork = await crypto.subtle.digest('SHA-256', contentNetwork);
            //contentNetwork = await crypto.subtle.digest('SHA-256', contentNetwork);

            //var verifyResult = await this.rsaVerify(contentNetwork, contentSignature, publicKey);
            //console.log("verifyResult" ,verifyResult)
            /*if (!verifyResult) {
                throw "network verify error";
            }*/
            return new TextDecoder().decode(contentNetwork);
        },

        async makeNetwork() {
            var n = await this.loadNetworkFromZip64(this.NetworkContainerDefault)
            //console.log("NETWORK", n)
            return n;
            //const response = await axios.get(sourceUrl);
            //return response.data;
        },

        makePeerHttp(routerHost, processor, localAddress) {
            var peerHttp = {
                afterId: 0,
                routerHost: routerHost,
                processor: processor,
                localAddress: localAddress,
                start() {
                    this.timer = window.setInterval(this.backgroundWorker, 100, this);
                },
                backgroundWorker(ctx) {
                    ctx.requestXchgrRead(ctx.localAddress);
                },
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
                        const response = await axios.post("http://" + this.routerHost + "/api/r", formData, {
                            headers: formData.headers
                        },);
                        receivedData = response.data;

                    } catch (ex) {
                        console.log(ex);
                        this.requestXchgrReadProcessing = false;
                    }
                    this.requestXchgrReadProcessing = false;

                    if (receivedData == undefined) {
                        return;
                    }

                    // Process frames
                    var resultBA = xchg.base64ToArrayBuffer(receivedData)
                    var view = new DataView(resultBA);
                    var bytes = new Uint8Array(resultBA);
                    var lastId = view.getBigUint64(0, true);

                    this.afterId = Number(lastId)
                    var offset = 8
                    var size = view.byteLength;
                    try {
                        while (offset < size) {
                            if (offset + 128 <= size) {
                                var frameLen = view.getUint32(offset, true);
                                if (offset + frameLen <= size) {
                                    var frame = bytes.subarray(offset, offset + frameLen);
                                    await this.processor.processFrame(frame.buffer.slice(frame.byteOffset, frame.byteOffset + frameLen));
                                } else {
                                    break;
                                }
                                offset += frameLen;
                            } else {
                                break;
                            }
                        }
                    } catch (ex) {
                        console.log("process incoming frame exception:", ex);
                    }
                    return
                },

            };
            return peerHttp;
        },

        makeRemotePeer(localAddr, address, authData, localKeys) {
            return {
                counter: 0,
                localKeys: localKeys,
                remoteAddress: address,
                localAddress: localAddr,
                sessionId: 0,
                remotePublicKey: undefined,
                nonces: {},
                authData: authData,
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


                    this.sendFrame(t.destAddress, frame);
                },

                async sendFrameToRouter(node, formData) {
                    try {
                        await axios.post("http://" + node + "/api/w", formData, {
                            headers: formData.headers
                        },);
                    } catch (ex) {
                        console.log("send exception: ", ex);
                    }
                },

                async sendFrame(destAddress, frame) {
                    var frame64 = xchg.arrayBufferToBase64(frame);
                    const formData = new FormData();
                    formData.append('d', frame64);

                    var nodes = await xchg.getNodesByAddress(destAddress);
                    for (var i = 0; i < nodes.length; i++) {
                        var node = nodes[i];
                        this.sendFrameToRouter(node, formData);
                    }

                },

                async processFrame21(receivedNonce, receivedPublicKey) {
                    if (!this.nonces.check(receivedNonce)) {
                        throw "Wrong nonce in frame 21"
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
                    //this.authData = this.authData;

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

                        console.log("sending auth data", this.authData);

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
                    var result = await this.executeTransaction(this.sessionId, frame, this.aesKey);

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

                async executeTransaction(sessionId, data, aesKeyOriginal) {
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


                        await this.sendFrame(t.destAddress, tBlockBA);
                        offset += currentBlockSize;
                    }

                    for (var i = 0; i < 100; i++) {
                        if (t.complete) {
                            delete this.outgoingTransactions[transactionId];
                            if (t.err !== undefined) {
                                //console.log("exec transaction error", t);
                                throw t.err
                            }

                            return t.result;
                        }
                        await xchg.sleep(10);
                    }

                    var allowToResetSession = true;
                    if (aesKeyOriginal.byteLength == 32 && this.aesKey.byteLength == 32) {
                        var aesKeyOriginalView = new DataView(aesKeyOriginal);
                        var aesKeyView = new DataView(this.aesKey);
                        for (var i = 0; i < 32; i++) {
                            if (aesKeyView.getUint8(i) != aesKeyOriginalView.getUint8(i)) {
                                allowToResetSession = false;
                            }
                        }
                    }

                    if (allowToResetSession) {
                        this.sessionId = 0;
                        this.sessionNonceCounter = 1;
                        this.aesKey = new ArrayBuffer(0);
                    }
                    throw "transaction timeout";
                },
            };
        },

        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },

        async test11() {
            var privateKeyBS64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4T69E5NAQjf8yZDe1spPizbGkgmqYxr+0ry3NIYNkkpfa4GpwP5FFeg8/Zk22SNHqFy9txMkwVfxATLj2tB/BcqqjhUxq85unQlGxAyYatsy5VcxOronqizNjjd37/MEOHW7V3anK0sHes+BGat/2t10tZFWhP+KNF4l0D2SusmZ+iD/C+Yv8UAFtWAk9zpcUY6MnGm0Tv/FCVkiwbaUDwfz29meQnbse24iRxgRPQ7F1TLiLInir4savKD555hPTAEFIjd0Jetv3RUyF4qaRjko8bfe7F0GSXtQtIimu3+5oaroxKxg3W9RFr3BKVmGc1AD2LHNHYSER3L9NhUR1AgMBAAECggEAJWxwnyGCqcnbRmUY9rjC1GuFpWyhrlG0vUBQoXUrk7E8SkIE+rO9kIjfLbVdFCUnEkwQ4k3xt/HNnVS2vckHJaVdxoQbZx/9u/F4WuPTydrSKNOl/1frQwdusMkuiKrinDYXui8e+cLfgJOvdzzeKt9CeSQFSw+ItbNQwpMZk2rnho6iTMPXiiKj6pfec7I2miNUFHQEWt698fFaLzmKc/qSTAmlBQyiiFQNsP1dieMXboV23gLaH4tVwoRsVgM6V6HAyhIbyNHzqGRXJB6uasytnrcSBLb646WepLnskpgBg+VZjBgE3r7PMoJ7raQBViD9Zyz4DVGZbzB315cVwQKBgQDLyE9GyfB4vqgj863puVjlgnhBFmcZops7yI469UuwGd5WQ9tErn9Tx0LrSk8/PQIkOAHwit8F2UNlQEjq1HWOXWjI0wu67okOs8ax8a5gOIistBKfezK08SyIy2HXi9dKU673pasx5vamDhpm3wis3LP3/KLhrw0Wfjhy+bOF0QKBgQDnihtUXWW4MBbn5dMeUFTKefgw/kmxnTc9FyR9YJDBJ0b4vOsi6I0HuuQzOCFS3qXLdmlmkhfGk8089fBWAQ8rlQZUvMl9XyX3T7EEL8kIKUpnAS1o1jzb/ls1RU5735L/ngSzr0V5fT7Da74WSXhRk3esUkZserpLx0JbXtMpZQKBgQCWrGf5dkyoaogV9RHtE49oO1zA+1iF+tX+kR6g90fcUHQ1onyYvtEEV/vhzxLjNi/EKek9OuEGCQus7Kg9gZPeDLDydCFjOQX76e8LGSCOop5j2809QDFQ2lXMW1zfq9UmbtOa5lK7VgOe6iSZVWWrspAa1yBz8COkMvV4Baq4UQKBgCDuQo7QLcxxgoB+7nTsRfL6P/Nv5zlMu/ODXBw85LmkBXMRI3w2iQBlc1lZjVvE8N2sPLdq5djHYrRd4k3JHsg7DMh2hU3Af5zaB7optbTkcoGN6FB1z/gWCBDeh5gUp0qVxeNsdTwfNRMEOufekS9BAw9OMFfzaJWohGaMaQoFAoGBAMuwwMYAhUuMcAHuhzy52/KBYcSLcqigsrrQzgdj3x8X/CZuFvez1ErBbgn+IjVgx3teZfRVzsvblEOo4yrohkMPfmWTgH1AHNSTDeBnPsw3lzrk+DdWDYCiUWkgRr+tEIJF7KMreNHvR5bK7is7UFowd9FcOGnPe8aN/Ww4H+Px"
            var publicKeyBS64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuE+vROTQEI3/MmQ3tbKT4s2xpIJqmMa/tK8tzSGDZJKX2uBqcD+RRXoPP2ZNtkjR6hcvbcTJMFX8QEy49rQfwXKqo4VMavObp0JRsQMmGrbMuVXMTq6J6oszY43d+/zBDh1u1d2pytLB3rPgRmrf9rddLWRVoT/ijReJdA9krrJmfog/wvmL/FABbVgJPc6XFGOjJxptE7/xQlZIsG2lA8H89vZnkJ27HtuIkcYET0OxdUy4iyJ4q+LGryg+eeYT0wBBSI3dCXrb90VMheKmkY5KPG33uxdBkl7ULSIprt/uaGq6MSsYN1vURa9wSlZhnNQA9ixzR2EhEdy/TYVEdQIDAQAB"
            var signature64 = "ezSPgdjI4dXd20xMObVGUFnNuW9WOHfL5Aw07jDFDiwjd3zL+HdPcAyCTmG09YlvIdMbTFWFkGuCJZqcjDDbzU5x64y29xxM7zKOq75nDTiXiOsvKp5uX0/tGWseyajniz+MCbaHhJ4buhwybFXnkYMdKPzL9LrXrOtejbQ/A1OnwN2QrJY7tkCbfBGZ/2o5bxgPZWtl53gGsOXNlsjMw8CWk7i7u1UIT0OKEwKpdgnfPA+QwyOUR4lOv7Tx0Nib20vCp5nIUajMgQsRamDKzp0hZLBTibpXJ/j1vRML4JVp3Eabj5wf01PCNfKJ1Ur3S/WIDSRtdOM1FutIq8Qvjg=="
            var privateKeyBS = this.base64ToArrayBuffer(privateKeyBS64);
            var publicKeyBS = this.base64ToArrayBuffer(publicKeyBS64);
            var signature = this.base64ToArrayBuffer(signature64);
            var privateKeyBSHash = await crypto.subtle.digest('SHA-256', privateKeyBS);
            var publicKeyBSHash = await crypto.subtle.digest('SHA-256', publicKeyBS);
            console.log("privateKeyBSHash", privateKeyBSHash);
            console.log("publicKeyBSHash", publicKeyBSHash);

            var privateKeyForSigning = await window.crypto.subtle.importKey(
                "pkcs8",
                privateKeyBS,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256",
                },
                true,
                ["sign"]
            );
            console.log("privateKeyForSigning", privateKeyForSigning)

            var publicKey = await window.crypto.subtle.importKey("spki",
                publicKeyBS,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256"
                },
                true,
                ["verify"]
            );
            console.log("publicKey", publicKey);
            var exportedPublicKey = await window.crypto.subtle.exportKey("spki", publicKey);
            exportedPublicKey = this.arrayBufferToBase64(exportedPublicKey)
            console.log("exportedPublicKey", exportedPublicKey);


            var dataToVerify = new ArrayBuffer(3)
            var dataToVerifyView = new DataView(dataToVerify);
            dataToVerifyView.setUint8(0, 42)
            dataToVerifyView.setUint8(1, 43)
            dataToVerifyView.setUint8(2, 44)

            var hash = await crypto.subtle.digest('SHA-256', dataToVerify);
            //hash = await crypto.subtle.digest('SHA-256', hash);
            hash = dataToVerify;

            var resSign = await window.crypto.subtle.sign(
                {
                    name: "RSA-PSS",
                    saltLength: 32,
                },
                privateKeyForSigning,
                dataToVerify
            );
            console.log("resSign", resSign);      

            var res = await window.crypto.subtle.verify(
                {
                    name: "RSA-PSS",
                    saltLength: 32,
                },
                publicKey,
                signature,
                //resSign,
                hash,
            );

            console.log(publicKey)
            console.log(signature) // 
            console.log(hash) // OK

            console.log("VERIFY", res);            
        }
    }
}
