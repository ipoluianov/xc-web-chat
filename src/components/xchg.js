let xchg = new makeXchg();
export default xchg;

import axios from "axios";
import JSZip from "jszip";

function makeXchg() {


    return {
        base64ToArrayBuffer(base64string) {
            let binary_string = window.atob(base64string);
            let len = binary_string.length;
            let bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes.buffer;
        },

        binaryStringToArrayBuffer(binaryString) {
            let len = binaryString.length;
            let bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        },

        arrayBufferToBase64(buffer) {
            let binary = "";
            let bytes = new Uint8Array(buffer);
            let len = bytes.byteLength;
            for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
        },

        arrayBufferToBinaryString(arrayBuffer) {
            let binaryString = "";
            let bytes = new Uint8Array(arrayBuffer);
            let len = bytes.byteLength;
            for (let i = 0; i < len; i++) {
                binaryString += String.fromCharCode(bytes[i]);
            }
            return binaryString;
        },

        async addressFromPublicKey(publicKey) {
            let publicKeyBS = await this.rsaExportPublicKey(publicKey);
            let publicKeyBSHash = await crypto.subtle.digest('SHA-256', publicKeyBS);
            let addressBS = publicKeyBSHash.slice(0, 30);
            return this.addressBSToAddress32(addressBS);
        },

        addressToAddressBS(address) {
            let addressBS = xchg.decode32(address)
            return this.binaryStringToArrayBuffer(addressBS);
        },

        addressBSToAddress32(addressBS) {
            let address32 = xchg.encode32(this.arrayBufferToBinaryString(addressBS))
            return "#" + address32.toLowerCase();
        },

        address32ToAddressBS(address32) {
            if (address32 === undefined) {
                return new ArrayBuffer(30);
            }
            address32 = address32.replaceAll("#", "")
            let addressBinaryString = xchg.decode32(address32)
            return this.binaryStringToArrayBuffer(addressBinaryString);
        },

        async rsaEncrypt(arrayBufferToEncrypt, publicKey) {
            let res = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                publicKey,
                arrayBufferToEncrypt
            );
            return res;
        },

        async rsaDecrypt(arrayBufferEncrypted, privateKey) {
            let res = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                arrayBufferEncrypted
            );
            return res;
        },

        async rsaSign(arrayBufferEncrypted, privateKey) {
            let exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);
            let privateKeyForSigning = await window.crypto.subtle.importKey(
                "pkcs8",
                exportedPrivateKey,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256",
                },
                true,
                ["sign"]
            );


            let res = await window.crypto.subtle.sign(
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
            let exportedPublicKey = await window.crypto.subtle.exportKey("spki", publicKey);
            let publicKeyForVerify = await window.crypto.subtle.importKey(
                "spki",
                exportedPublicKey,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256",
                },
                true,
                ["verify"]
            );

            //console.log("Verify", publicKeyForVerify, signature, dataToVerify)

            let res = await window.crypto.subtle.verify(
                {
                    name: "RSA-PSS",
                    saltLength: 32,
                },
                publicKeyForVerify,
                signature,
                dataToVerify,
            );

            //console.log("VERIFY", res);

            return res;
        },

        async aesEncrypt(arrayBufferToEncrypt, aesKey) {

            let aesKeyNative = await window.crypto.subtle.importKey("raw", aesKey,
                {
                    name: "AES-GCM",
                },
                true,
                ["encrypt", "decrypt"]);

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            let res = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    length: 256,
                    iv: iv,
                },
                aesKeyNative,
                arrayBufferToEncrypt
            );

            let vRes = new DataView(res);

            let result = new ArrayBuffer(iv.length + vRes.buffer.byteLength);

            let v = new DataView(result);
            for (let i = 0; i < iv.length; i++) {
                v.setUint8(i, iv.at(i))
            }
            for (let i = 0; i < vRes.buffer.byteLength; i++) {
                v.setUint8(i + iv.length, vRes.getUint8(i))
            }

            return result;
        },

        async aesDecrypt(arrayBufferEncrypted, aesKey) {
            let aesKeyNative = await window.crypto.subtle.importKey("raw", aesKey,
                {
                    name: "AES-GCM",
                },
                true,
                ["encrypt", "decrypt"]);


            let bs = new Uint8Array(arrayBufferEncrypted);
            let iv = bs.subarray(0, 12);
            let ch = bs.subarray(12);
            let res = await window.crypto.subtle.decrypt(
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
            let exportedPublicKey = await window.crypto.subtle.exportKey("spki", publicKey);
            return exportedPublicKey;
        },

        async rsaImportPublicKey(publicKeyBA) {
            let publicKey = await window.crypto.subtle.importKey("spki",
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
            let keyPair = await window.crypto.subtle.generateKey(
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
            let content = await zip.generateAsync({ type: "arrayBuffer" });
            return content
        },

        async unpack(baZIP) {
            //let baZIP = this.base64ToArrayBuffer(zip64);
            let zip = await JSZip.loadAsync(baZIP);
            let content = await zip.files["data"].async('arrayBuffer')
            return content;
        },

        makeTransaction() {
            let t = {
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
                    let result = new ArrayBuffer(128 + this.data.byteLength);
                    let view = new DataView(result);
                    view.setUint32(0, 128 + this.data.byteLength, true);
                    view.setUint8(8, this.frameType);
                    view.setBigUint64(16, BigInt(this.transactionId), true);
                    view.setBigUint64(24, BigInt(this.sessionId), true);
                    view.setUint32(32, this.offset, true);
                    view.setUint32(36, this.totalSize, true);
                    let srcAddressBS = xchg.address32ToAddressBS(this.srcAddress)
                    let srcAddressBSView = new DataView(srcAddressBS);
                    for (let i = 0; i < srcAddressBS.byteLength; i++) {
                        view.setUint8(40 + i, srcAddressBSView.getUint8(i));
                    }
                    let destAddressBS = xchg.address32ToAddressBS(this.destAddress)
                    let destAddressBSView = new DataView(destAddressBS);
                    for (let i = 0; i < destAddressBS.byteLength; i++) {
                        view.setUint8(70 + i, destAddressBSView.getUint8(i));
                    }

                    let dataView = new DataView(this.data);
                    for (let i = 0; i < this.data.byteLength; i++) {
                        view.setUint8(128 + i, dataView.getUint8(i));
                    }
                    return result;
                },

                appendReceivedData(transaction) {
                    if (this.receivedFrames.length < 1000) {
                        let found = false;
                        for (let i = 0; i < this.receivedFrames.length; i++) {
                            let tr = this.receivedFrames[i];
                            if (tr.offset == transaction.offset) {
                                found = true;
                                break;
                            }
                        }

                        if (!found) {
                            this.receivedFrames.push(transaction);
                        }
                    }

                    let receivedDataLen = 0;
                    for (let i = 0; i < this.receivedFrames.length; i++) {
                        let tr = this.receivedFrames[i];
                        receivedDataLen += tr.data.byteLength;
                    }

                    if (receivedDataLen == transaction.totalSize) {
                        this.result = new ArrayBuffer(transaction.totalSize);
                        for (let i = 0; i < this.receivedFrames.length; i++) {
                            let tr = this.receivedFrames[i];
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
            let ns = new ArrayBuffer(count * 16);
            return {
                nonces: ns,
                noncesCount: count,
                currentIndex: 0,
                complexity: 0,
                async fillNonce(index) {
                    if (index >= 0 && index < this.noncesCount) {
                        let view = new DataView(this.nonces);
                        view.setUint32(index * 16, index, true);
                        view.setUint8(index * 16 + 4, this.complexity);
                        const randomArray = new Uint8Array(11);
                        await crypto.getRandomValues(randomArray);
                        for (let i = 0; i < 11; i++) {
                            view.setUint8(5 + i, randomArray[i]);
                        }
                    }
                },
                async next() {
                    await this.fillNonce(this.currentIndex);
                    let result = new ArrayBuffer(16);
                    let resultView = new DataView(result);
                    let view = new DataView(this.nonces);
                    for (let i = 0; i < 16; i++) {
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
                    let view = new DataView(nonce);
                    let index = view.getUint32(0, true);
                    if (index < 0 || index >= this.noncesCount) {
                        return false;
                    }

                    let viewNonces = new DataView(this.nonces);

                    for (let i = 0; i < 16; i++) {
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
            let destView = new DataView(destBA);
            let srcView = new DataView(srcBA);
            let size = srcOffsetEnd - srcOffsetBegin;
            for (let i = 0; i < size; i++) {
                let srcOffset = srcOffsetBegin + i;
                let targetOffset = destOffset + i;
                if (targetOffset >= 0 && targetOffset < destBA.byteLength) {
                    destView.setUint8(targetOffset, srcView.getUint8(srcOffset));
                }
            }
        },

        makeSnakeCounter(size, initValue) {
            let initData = new ArrayBuffer(size);
            let initDataView = new DataView(initData);
            for (let i = 0; i < size; i++) {
                initDataView.setUint8(i, 1);
            }
            let result = {
                size: size,
                lastProcessed: BigInt(-1),
                data: initData,
                testAndDeclare(counter) {
                    counter = BigInt(counter)
                    if (counter < (this.lastProcessed - BigInt(this.size))) {
                        return false;
                    }

                    if (counter > this.lastProcessed) {
                        let shiftRange = counter - this.lastProcessed;
                        let dataView = new DataView(this.data);
                        let newData = new ArrayBuffer(this.size);
                        let newDataView = new DataView(newData);
                        for (let i = 0; i < this.size; i++) {
                            let b = 0;
                            let oldAddressOfCell = BigInt(i) - shiftRange;
                            if (oldAddressOfCell >= 0 && oldAddressOfCell < this.size) {
                                b = dataView.getUint8(Number(oldAddressOfCell));
                            }
                            newDataView.setUint8(i, b);
                        }
                        this.data = newData;
                        let dataViewN = new DataView(this.data);
                        dataViewN.setUint8(0, 1);
                        this.lastProcessed = counter;
                        return true;
                    }

                    let index = this.lastProcessed - counter;
                    if (index >= 0 && index < this.size) {
                        let dataView = new DataView(this.data);
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
            let a = this.base32a;
            let pad = this.base32pad;
            let len = s.length;
            let o = "";
            let w, c, r = 0, sh = 0; // word, character, remainder, shift
            for (let i = 0; i < len; i += 5) {
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
            let padlen = 8 - (o.length % 8);
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
            let len = s.length;
            let apad = this.base32a + this.base32pad;
            let v, x = 0, bits = 0, c, o = '';

            s = s.toUpperCase();

            for (let i = 0; i < len; i += 1) {
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

        async getNodesByAddress(network, address) {
            let result = [];

            if (address == undefined) {
                return [];
            }

            //let network = await xchg.makeNetwork();
            //console.log("Network", network);


            address = address.replaceAll("#", "").toLowerCase();
            let addressBA = new TextEncoder().encode(address);
            let addressBAHash = await crypto.subtle.digest('SHA-256', addressBA);
            let addressBAHashHex = xchg.buf2hex(addressBAHash);

            let preferredRange = undefined
            let preferredRangeScores = 0

            for (let i = 0; i < network.ranges.length && i < addressBAHashHex.length; i++) {
                let range = network.ranges[i];
                //console.log("range", range);
                let rangeScores = 0;
                for (let cIndex = 0; cIndex < range.prefix.length; cIndex++) {
                    let chInRange = range.prefix[cIndex];
                    let chInAddressBAHashHex = addressBAHashHex[cIndex];
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
                for (let i = 0; i < preferredRange.hosts.length; i++) {
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

        makeXPeerStat() {
            return {
                R_count: 0,
                W_count: 0,
                processedFrames: 0,
            };
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
                network: undefined,
                stat: this.makeXPeerStat(),
                async start() {
                    this.keyPair = await xchg.generateRSAKeyPair();
                    this.localAddress = await xchg.addressFromPublicKey(this.keyPair.publicKey);
                    console.log("start local address:", this.localAddress);
                    this.timer = window.setInterval(this.backgroundWorker, 100, this);
                    this.nonces = xchg.makeNonces(1000);

                    this.network = await xchg.makeNetwork();
                    console.log("Network", this.network);

                    let nodes = await xchg.getNodesByAddress(this.network, "#3xk6hf4jegiurclldhl74ddf2pqhrsozr5lvhavs6phr4uku");

                    for (let i = 0; i < nodes.length; i++) {
                        let addr = nodes[i];
                        let peerHttp = xchg.makePeerHttp(addr, this, this.localAddress, this.stat);
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
                currentRouters() {
                    let res = "";
                    for (let r in this.routers) {
                        res += r;
                        res += " "
                    }
                    return res;
                },
                async call(address, authData, func, data) {
                    if (address.length != 49) {
                        throw "wrong address";
                    }

                    console.log("***************authData", authData);

                    let remotePeer
                    if (this.remotePeers[address] != undefined) {
                        remotePeer = this.remotePeers[address];
                    } else {
                        remotePeer = xchg.makeRemotePeer(this.localAddress, address, authData, this.keyPair, this.network);
                        remotePeer.start();
                        this.remotePeers[address] = remotePeer;
                    }
                    remotePeer.authData = authData;
                    return await remotePeer.call(func, data);
                },

                lastPurgeSessionsDT: 0,
                async purgeSessions() {
                    let now = Date.now();
                    if (now - this.lastPurgeSessionsDT > 5 * 60 * 1000) {
                        let found = true;
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
                    this.stat.processedFrames++;

                    let t = this.parseTransaction(frame);
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
                    let foundForDelete = true;
                    while (foundForDelete) {
                        foundForDelete = false;
                        for (const trCode in this.incomingTransactions) {
                            let incomingTransaction = this.incomingTransactions[trCode]
                            if (Date.now() - incomingTransaction.beginDT > 10000) {
                                delete this.incomingTransactions[trCode];
                                foundForDelete = true;
                                break;
                            }
                        }
                    }

                    let trCode = t.srcAddress + "/" + t.transactionId;
                    let incomingTransaction = this.incomingTransactions[trCode];
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


                    let response = await this.onEdgeReceivedCall(incomingTransaction.sessionId, incomingTransaction.data);
                    if (response != undefined) {
                        let trResponse = xchg.makeTransaction();
                        trResponse.frameType = 0x11;
                        trResponse.transactionId = incomingTransaction.transactionId;
                        trResponse.sessionId = incomingTransaction.sessionId;
                        trResponse.offset = 0;
                        trResponse.totalSize = response.byteLength;
                        trResponse.srcAddress = this.localAddress;
                        trResponse.destAddress = incomingTransaction.srcAddress;
                        trResponse.data = response;

                        let offset = 0;
                        let blockSize = 1024;
                        while (offset < trResponse.data.byteLength) {
                            let currentBlockSize = blockSize;
                            let restDataLen = trResponse.data.length - offset;
                            if (restDataLen < currentBlockSize) {
                                currentBlockSize = restDataLen;
                            }

                            let trBlock = xchg.makeTransaction();
                            trBlock.frameType = 0x11;
                            trBlock.transactionId = trResponse.transactionId;
                            trBlock.sessionId = trResponse.sessionId;
                            trBlock.offset = offset;
                            trBlock.totalSize = response.byteLength;
                            trBlock.srcAddress = trResponse.srcAddress;
                            trBlock.destAddress = trResponse.destAddress;
                            trBlock.data = trResponse.data.slice(offset, offset + currentBlockSize);

                            let responseFrameBlock = trBlock.serialize()
                            await this.sendFrame(trBlock.destAddress, responseFrameBlock);
                            offset += currentBlockSize;
                        }
                    }

                },
                processFrame11(t) {
                    let remotePeer = this.remotePeers[t.srcAddress];
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

                    let nonce = t.data.slice(0, 16)
                    //let nonceHash = await crypto.subtle.digest('SHA-256', nonce);
                    let addressStringBytes = t.data.slice(16);
                    let address = new TextDecoder().decode(addressStringBytes);
                    if (address !== this.localAddress) {
                        return
                    }

                    let publicKeyBS = await xchg.rsaExportPublicKey(this.keyPair.publicKey);
                    let signature = await xchg.rsaSign(nonce, this.keyPair.privateKey);

                    let response = new ArrayBuffer(16 + 256 + publicKeyBS.byteLength);
                    xchg.copyBA(response, 0, nonce);
                    xchg.copyBA(response, 16, signature);
                    xchg.copyBA(response, 16 + 256, publicKeyBS);

                    let trResponse = xchg.makeTransaction();
                    trResponse.frameType = 0x21;
                    trResponse.transactionId = 0;
                    trResponse.sessionId = 0;
                    trResponse.offset = 0;
                    trResponse.totalSize = response.byteLength;
                    trResponse.srcAddress = this.localAddress;
                    trResponse.destAddress = t.srcAddress;
                    trResponse.data = response;

                    let frResponse = trResponse.serialize();
                    this.sendFrame(trResponse.destAddress, frResponse);
                },
                async processFrame21(t) {
                    // [0:16] - original nonce
                    // [16:16+256] - signature of SHA256(nonce)
                    // [16+256:] - remote public key
                    if (t.data.byteLength < 16 + 256) {
                        return
                    }

                    let receivedNonce = t.data.slice(0, 16);
                    let receivedPublicKeyBS = t.data.slice(16 + 256);
                    let receivedPublicKey = {}
                    try {
                        receivedPublicKey = await xchg.rsaImportPublicKey(receivedPublicKeyBS);
                    }
                    catch (ex) {
                        throw "cannot import remote public key";
                    }
                    let receivedAddress = await xchg.addressFromPublicKey(receivedPublicKey);
                    let remotePeer = this.remotePeers[receivedAddress];
                    if (remotePeer === undefined) {
                        return
                    }

                    //let nonceHash = await crypto.subtle.digest('SHA-256', receivedNonce);
                    let signature = t.data.slice(16, 16 + 256);
                    let verifyRes = await xchg.rsaVerify(receivedNonce, signature, receivedPublicKey);
                    if (verifyRes !== true) {
                        console.log("verifyRes", verifyRes);
                        throw "signature verify error";
                    }

                    remotePeer.processFrame21(receivedNonce, receivedPublicKey);
                },
                parseTransaction(frame) {
                    let t = {}
                    let view = new DataView(frame)
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
                    this.stat.W_count++;
                    let frame64 = xchg.arrayBufferToBase64(frame);
                    const formData = new FormData();
                    formData.append('d', frame64);
                    let nodes = await xchg.getNodesByAddress(this.network, destAddress);
                    for (let i = 0; i < nodes.length; i++) {
                        let node = nodes[i];
                        this.sendFrameToRouter(node, formData);
                    }
                },

                async onEdgeReceivedCall(sessionId, data) {
                    let encrypted = false;
                    let session = undefined;
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
                        let dataView = new DataView(data);
                        let callNonce = dataView.getBigUint64(0, true);
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

                    let dataView = new DataView(data);

                    let funcLen = dataView.getUint8(0);
                    if (data.byteLength < 1 + funcLen) {
                        throw "wrong data frame len(fn)";
                    }

                    let funcNameBA = data.slice(1, 1 + funcLen);
                    let funcName = new TextDecoder().decode(funcNameBA);
                    let funcParameter = data.slice(1 + funcLen);

                    let response = new ArrayBuffer(0);

                    try {
                        if (sessionId == 0) {
                            let processed = false;
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
                        let responseFinal = new ArrayBuffer(1 + response.byteLength);
                        let responseFinalView = new DataView(responseFinal);
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
                    let errorBA = new TextEncoder().encode(errorString).buffer;
                    let response = new ArrayBuffer(1 + errorBA.byteLength);
                    let responseView = new DataView(response);
                    responseView.setUint8(0, 1);
                    xchg.copyBA(response, 1, errorBA);
                    return response;
                },

                async processFunction(funcName, funcParameter) {
                    //return new TextEncoder().encode(Date.now().toString()).buffer;
                    return this.onCall(funcName, funcParameter);
                },

                async processAuth(funcParameter) {
                    if (funcParameter.byteLength < 4) {
                        throw "processAuth: funcParameter.byteLength < 4";
                    }

                    let funcParameterView = new DataView(funcParameter);

                    let remotePublicKeyBALen = funcParameterView.getUint32(0, true);
                    if (funcParameter.byteLength < 4 + remotePublicKeyBALen) {
                        throw "processAuth: funcParameter.byteLength < 4+remotePublicKeyBALen";
                    }
                    let remotePublicKeyBA = funcParameter.slice(4, 4 + remotePublicKeyBALen);
                    let remotePublicKey = await xchg.rsaImportPublicKey(remotePublicKeyBA);

                    let authFrameSecret = funcParameter.slice(4 + remotePublicKeyBALen);
                    let parameter = await xchg.rsaDecrypt(authFrameSecret, this.keyPair.privateKey);
                    if (parameter.byteLength < 16) {
                        throw "processAuth: parameter.byteLength < 16";
                    }
                    let nonce = parameter.slice(0, 16);

                    this.nonces.check(nonce);

                    let authData = parameter.slice(16);
                    if (this.onAuth !== undefined) {
                        this.onAuth(authData);
                    }

                    let sessionId = this.nextSessionId;
                    this.nextSessionId++;

                    let session = xchg.makeSession();
                    session.id = sessionId;
                    session.lastAccessDT = Date.now();
                    session.aesKey = new ArrayBuffer(32);
                    let aesView = new DataView(session.aesKey);
                    const randomArray = new Uint8Array(32);
                    await crypto.getRandomValues(randomArray);
                    for (let i = 0; i < 32; i++) {
                        aesView.setUint8(i, randomArray[i]);
                    }
                    session.snakeCounter = xchg.makeSnakeCounter(100, 1);
                    this.sessions[sessionId] = session;

                    let response = new ArrayBuffer(8 + 32);
                    let responseView = new DataView(response);
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

        NetworkContainerDefault: "UEsDBBQACAAIAGqPdFUAAAAAAAAAAAAAAAAMAAkAbmV0d29yay5qc29uVVQFAAHoXHpj1NBNasMwEAXgvU4xzDoo/pV/7tBeoJii2JNE1JaFJGhpyN2L0rQLU2i2s9Hi6fH4pIsAtHoh7AGftLHPFHEnAKNZKES9OOwhV6rtVFmrLN0Ya6LR86tbjY0Be3gRAHiO0fX7vZ5nGkmO67K3FN9X/yY/jZMHHUhVaXjbtBQfbK7+9FdTwJBUXtsT/WguAgDQeTqaj/Sw7LYHeF7Dr/jeAkA9TZ5CyrGuZNnIppS5yvo2a78hqbT9o1t83f07VBTdI0PpHMR9ccvPefML3vySN7/iza958xVvfsOb3/Lmd7z5mjf/wJs/8uZPvPnEm3/kwxcwiOtXAAAA//9QSwcIYD6Ex/sAAADGDAAAUEsDBBQACAAIAGqPdFUAAAAAAAAAAAAAAAAQAAkAc2lnbmF0dXJlLmJhc2U2NFVUBQAB6Fx6YwTAzYJjMAAA4AfqQcuoOMwhiL8NaUKl3ChlU7GmjWKffr6t8LuxcPfjC/JTQIGjf+mGhiYsFznIK57FhbjQtoL+PHcqVSc4G4c4615VatgYR8iaOONV3AvgpMnn8TOUsbTqN9Vwg1Zwjz26VsjWqsneb38piW7IzP+dmzdmrZIL9B7UzE349u2t04zJC0cpQuUlyUnV0ixsmauOsIOr/GOT0vHY3MmncIeEl1GxATHnDMAFPIuPcywBZ/yZ+XyUtZP9T7NubcLttrdzCOZSjXdiIXfUYYkmz7lis+nDeoLk+XRaaokhCvqgf8DswJKrDrW2jkX/yn8u0BbtKga2lVZ78W8qOP+hOXVNfZN+RfhAoq/gZKTIqCK2o3BY8A6/v38DAAD//1BLBwgHvBVNJgEAAFgBAABQSwECFAAUAAgACABqj3RVYD6Ex/sAAADGDAAADAAJAAAAAAAAAAAAAAAAAAAAbmV0d29yay5qc29uVVQFAAHoXHpjUEsBAhQAFAAIAAgAao90VQe8FU0mAQAAWAEAABAACQAAAAAAAAAAAAAAPgEAAHNpZ25hdHVyZS5iYXNlNjRVVAUAAehcemNQSwUGAAAAAAIAAgCKAAAAqwIAAAAA",
        NetworkContainerEncryptedPrivateKey: "uTC09uvV2vNvwes9yj+bb80UbQh14JSFG22MSMFYgd6odNyqRw9jluBfWg4ZE38k/rugSyvchj23DN54QM3lQxuiqe35YaSvkdAsNxumOaSvsXbezY4iz/WljSfqMjKVPHtUl81RusgNZAAegp8XL7u8UBFREPSQGqhqQGggDcnp8qtXz13yo3NVFJ1Zq+kkfWT2EJyhhi+u3LIpPE4s8I/ht9LERqYeGsXbWBxCwHWHa9MWHIsa6B2naL1VEEUdpQ1GvHNY62FWFMcjpUbXNJwNDEo2GUYXYv3cbj/HFrEebhglB6FomyjkHXWEPQf7CVZx3TVjZfmCTBL5f6ud/5MOvPX2aAbeVtvLw5fT5ZocnPExAMoFlYmwfSZWRauGFAavV7FLHvtkdGDQn33Z1adkL/Bgnz68ijR9SjA+XfQn7d2OTYIgN9FhhN1m8a4wovx4geRxFxJhe0kUVDHt+gXFPavBAcNb/iGu10CDk23WkFaN+eVTRP7WKviVhUsiraTW0CsGr1E0HYy6SY0A6PbEgWEP2azg8jAZRKiYG0uLyy81JN9C55oSAXcNKooqblcX4bPB9tI1cy4zbdhj6GehfxRQ872ZsGwnpDzy3iiQstI7XYhUvQKctl7IPz4JN++sP1qUvkFaUfEeXFtzzgZ5d92qsaMqz+6yA5kFk792I+W3F/mJdQnqeLhNKN3e+PWj2UlPpjFOmcCg6d/pKHCZk6GWYHU/V37/rLYkI6uw63r6/xMmpukXcbYvH5yd/5Ej0ohrtwz3iR5ZzpXVBIOlapW50lvYoBPLpPFtIKCPj3GMp8jqut9OsiYqCCmOdTKa49regsyJtomVhU+o26i8EHrvgGqQdHhFgDY2XlUB6C/KgKuYuML/8DzTyc+0qxnxeVMwC5Ug+H8qaBJMBlj0p1TDnGIKU2B/fostvL980a6pu9OUhgbCkEvQk8ba6KbDIsVjsVV2bAGi2sx4Gsr5z6x8O0taW+pO2ZE8gjq4WNiF9iWvG4JPclux0NbNhz3CPmfxhC80is25r6KbYHm8UhCTmsa7scWxV60pArpJyyoFf65L4kvxrmEKHAvUQYXs02wQ3e/mqaJuIzkfPkJFqB0R8y68nFLf3XKZQNaBT6QKaMEBfg0/CSkHCPZMRJMu+Rn85w1n4dB+J5mRKo/0cSk+3zGbQR+NbjgNIMUb/pUkJwrKhEJppejRBuu9Yvolu+q/2rnbBEElz/OrOyqw2vP9bbv0Q0HB2JkYD97j8aPbg8Vw6SOfaoyGzbJ21LNNlfPAWF4skyi8RvEAXGRnGS/zRDkTSUqANK+unAMgRTxEFgK2b86BMQuCxm6kPAW0GdY0nqkGvrdTK6Gs+8aLSI21dPHN/n2OCoIZvOqu3l9v6mlHtONJqbvfsDFk64hztO2p0SdhVi84I19y/hMJQESkKorGVR5XH/mKCBcBanYtpKhOtQZdWNT9taImL9EKtTeXcOfjs8YPSCGunueYp+nDBSmhlrC/K1mVCBAaUXVTxe1YaVGrXRMlIYUIB2g+KkV0d7ZNxzhqNJcw1Aud322IXI9aB4c8HismCRUp7NkRmTPYlT/hBJUJ1hVCIYWvzNYXd2Cse6bksv8KSpYf1rJHszGlvlHD4T8VBs29i0XDb5UyGLmLeyYRGz4=",
        NetworkContainerPublicKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8V7FEvpzVo4sLhE3rIEmKwbLmNZkweZLucv/vxIbj3y8jpJiEGT3kQA9JvGscdsS85gca34WCfKdMJBKErUm28/UAWnDZeVUmQyxwGXs2jO/OLQukwJT76Umsu/KIfr7zKxkzfm7fTsJ8q1ZYuHgndi4OTblKqy/tSynyEYFnlbpEvmIAS2ZJblarxaG5VJo3YA5ZdO5FTcuaSkZ+9v4uMvcwFK9qIigJCS+xJa+ubgN9cv2RuHuQB7+Qw9bGbCjk9cSGnbV0ttwoVMZxFkT72lAXdp5/NLWcRpKnnjEvkWKjo21ROeH6hk4qfa30Q/Q+hLbPxhLlXX2r9sNEEZkWQIDAQAB",
        NetworkContainerFileNetwork: "network.json",
        NetworkContainerFileSignature: "signature.base64",

        async loadNetworkFromZip64(zip64) {
            let zipBA = xchg.base64ToArrayBuffer(zip64)
            let publicKeyBA = this.base64ToArrayBuffer(this.NetworkContainerPublicKey)
            let publicKey = await this.rsaImportPublicKey(publicKeyBA)
            let zip = await JSZip.loadAsync(zipBA);
            let contentNetwork = await zip.files[this.NetworkContainerFileNetwork].async('arrayBuffer')
            let contentSignature = await zip.files[this.NetworkContainerFileSignature].async('arrayBuffer')

            contentSignature = new TextDecoder().decode(contentSignature)
            contentSignature = xchg.base64ToArrayBuffer(contentSignature)

            let verifyResult = await this.rsaVerify(contentNetwork, contentSignature, publicKey);
            if (!verifyResult) {
                throw "network verify error";
            }

            return JSON.parse(new TextDecoder().decode(contentNetwork));
        },

        async makeNetwork() {
            console.log("-=makeNetwork=-")
            let network = await this.loadNetworkFromZip64(this.NetworkContainerDefault)
            //let networks = []
            for (let i = 0; i < network.initial_points.length; i++) {
                try {
                    let sourceUrl = network.initial_points[i];
                    console.log("sourceUrl", sourceUrl);
                    const response = await axios.get(sourceUrl);
                    //console.log("RESP:", response)
                    //response = new TextDecoder().decode(response.data)
                    let n = await this.loadNetworkFromZip64(response.data)
                    if (n.timestamp > network.timestamp) {
                        network = n;
                    }
                } catch (ex) {
                    console.log("network file error", ex);
                }
            }

            //console.log("NETWORK", n)
            return network;
            //const response = await axios.get(sourceUrl);
            //return response.data;
        },

        makePeerHttp(routerHost, processor, localAddress, stat) {
            let peerHttp = {
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
                    let buffer = new ArrayBuffer(8 + 8 + 30);
                    let bufferView = new DataView(buffer);
                    bufferView.setBigUint64(0, BigInt(this.afterId), true); // AfterId
                    bufferView.setBigUint64(8, BigInt(1024 * 1024), true); // MaxSize
                    let addressBS = xchg.addressToAddressBS(address);
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
                    let receivedData;
                    try {
                        let frame = this.makeXchgrReadRequest(address);
                        const formData = new FormData();
                        formData.append('d', frame);
                        stat.R_count++;
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
                    let resultBA = xchg.base64ToArrayBuffer(receivedData)
                    let view = new DataView(resultBA);
                    let bytes = new Uint8Array(resultBA);
                    let lastId = view.getBigUint64(0, true);

                    this.afterId = Number(lastId)
                    let offset = 8
                    let size = view.byteLength;
                    try {
                        while (offset < size) {
                            if (offset + 128 <= size) {
                                let frameLen = view.getUint32(offset, true);
                                if (offset + frameLen <= size) {
                                    let frame = bytes.subarray(offset, offset + frameLen);
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

        makeRemotePeer(localAddr, address, authData, localKeys, network) {
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
                network: network,
                start() {
                    this.nonces = xchg.makeNonces(1000);
                    this.timer = window.setInterval(this.backgroundWorker, 200, this);
                },
                stop() {
                    window.clearInterval(this.timer)
                },
                backgroundWorker(/*ctx*/) {
                },
                async call(func, data) {
                    if (this.remotePublicKey === undefined) {
                        await this.requestPublicKey();
                    }

                    if (this.sessionId === 0) {
                        await this.auth();
                    }

                    let result = await this.regularCall(func, data, this.aesKey);
                    return result;
                },
                async requestPublicKey() {
                    let enc = new TextEncoder();
                    let addr = this.remoteAddress
                    let remoteAddressBS = enc.encode(addr);
                    let remoteAddressBSView = new DataView(remoteAddressBS.buffer);
                    let request = new ArrayBuffer(16 + remoteAddressBS.byteLength);
                    let requestView = new DataView(request);
                    let nonce = await this.nonces.next();
                    let nonceView = new DataView(nonce);
                    for (let i = 0; i < 16; i++) {
                        requestView.setUint8(i, nonceView.getUint8(i));
                    }
                    for (let i = 0; i < remoteAddressBS.byteLength; i++) {
                        requestView.setUint8(16 + i, remoteAddressBSView.getUint8(i));
                    }

                    let t = xchg.makeTransaction();
                    t.frameType = 0x20;
                    t.transactionId = 0;
                    t.sessionId = 0;
                    t.offset = 0;
                    t.totalSize = request.byteLength;
                    t.srcAddress = this.localAddress;
                    t.destAddress = this.remoteAddress;
                    t.data = request;
                    let frame = t.serialize()


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
                    let frame64 = xchg.arrayBufferToBase64(frame);
                    const formData = new FormData();
                    formData.append('d', frame64);

                    let nodes = await xchg.getNodesByAddress(this.network, destAddress);
                    for (let i = 0; i < nodes.length; i++) {
                        let node = nodes[i];
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
                    for (let i = 0; i < 100; i++) {
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
                        for (let i = 0; i < 100; i++) {
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
                        let nonce = await this.regularCall("/xchg-get-nonce", new ArrayBuffer(0), new ArrayBuffer(0));

                        if (nonce.byteLength != 16) {
                            throw "wrong nonce length";
                        }

                        // RSA-2048 public key as an ArrayBuffer
                        let localPublicKeyBA = await xchg.rsaExportPublicKey(this.localKeys.publicKey);

                        // This path will be encrypted with remote public key:
                        // received nonce and secret auth data
                        let authFrameSecret = new ArrayBuffer(16 + this.authData.byteLength);
                        xchg.copyBA(authFrameSecret, 0, nonce);
                        xchg.copyBA(authFrameSecret, 16, this.authData);

                        console.log("sending auth data", this.authData);

                        // Encrypt secret data (nonce and auth data) with RSA-2048
                        let encryptedAuthFrame = await xchg.rsaEncrypt(authFrameSecret, this.remotePublicKey);

                        // Prepare final auth frame
                        // [0:4] - length of local public key
                        // [4:PK_LEN] - local public key
                        // [PK_LEN:] - encrypted (RSA-2048) nonce and auth data
                        let authFrame = new ArrayBuffer(4 + localPublicKeyBA.byteLength + encryptedAuthFrame.byteLength);
                        let authFrameView = new DataView(authFrame);
                        authFrameView.setUint32(0, localPublicKeyBA.byteLength, true);
                        xchg.copyBA(authFrame, 4, localPublicKeyBA);
                        xchg.copyBA(authFrame, 4 + localPublicKeyBA.byteLength, encryptedAuthFrame);

                        // --------------------------------------------------
                        // Call Auth
                        let result = await this.regularCall("/xchg-auth", authFrame, new ArrayBuffer(0), new ArrayBuffer(0));
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
                        let resultView = new DataView(result);
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
                    let enc = new TextEncoder();
                    let funcBS = enc.encode(func);
                    funcBS = funcBS.buffer;
                    if (funcBS.byteLength > 255) {
                        throw "regularCall: func length > 255";
                    }

                    let encrypted = false;

                    // Check local RSA keys
                    if (this.localKeys === undefined) {
                        throw "localKeys === undefined";
                    }

                    // Session nonce counter must be incremented everytime
                    let sessionNonceCounter = this.sessionNonceCounter;
                    this.sessionNonceCounter++;

                    // Prepare frame
                    let frame = new ArrayBuffer(0);
                    if (aesKey !== undefined && aesKey.byteLength == 32) {
                        // Session is active
                        // Using AES encryption with ZIP
                        frame = new ArrayBuffer(8 + 1 + funcBS.byteLength + data.byteLength);
                        let frameView = new DataView(frame);
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
                        let frameView = new DataView(frame);
                        frameView.setUint8(0, funcBS.byteLength);
                        xchg.copyBA(frame, 1, funcBS);
                        xchg.copyBA(frame, 1 + funcBS.byteLength, data);
                    }

                    // Executing transaction with response waiting
                    let result = await this.executeTransaction(this.sessionId, frame, this.aesKey);

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

                    let resultData = new ArrayBuffer(0);
                    let resultView = new DataView(result);
                    if (resultView.getUint8(0) == 0) {
                        // Success
                        resultData = new ArrayBuffer(result.byteLength - 1);
                        xchg.copyBA(resultData, 0, result, 1);
                    }

                    if (resultView.getUint8(0) == 1) {
                        console.log("ERROR BIT: ", result);
                        resultData = new ArrayBuffer(result.byteLength - 1);
                        xchg.copyBA(resultData, 0, result, 1);
                        let dec = new TextDecoder();
                        throw dec.decode(resultData);
                    }

                    return resultData;
                },

                async processFrame11(transaction) {
                    let t = this.outgoingTransactions[transaction.transactionId];
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
                    let transactionId = this.nextTransactionId;
                    this.nextTransactionId++;

                    let t = xchg.makeTransaction();
                    t.frameType = 0x10;
                    t.transactionId = transactionId;
                    t.sessionId = sessionId;
                    t.offset = 0;
                    t.totalSize = data.byteLength;
                    t.data = data;
                    t.srcAddress = this.localAddress;
                    t.destAddress = this.remoteAddress;

                    this.outgoingTransactions[transactionId] = t;

                    let offset = 0;
                    let blockSize = 1024;
                    while (offset < data.byteLength) {
                        let currentBlockSize = blockSize;
                        let restDataLen = data.byteLength - offset;
                        if (restDataLen < currentBlockSize) {
                            currentBlockSize = restDataLen;
                        }

                        let tBlock = xchg.makeTransaction();
                        tBlock.frameType = 0x10;
                        tBlock.transactionId = transactionId;
                        tBlock.sessionId = sessionId;
                        tBlock.offset = offset;
                        tBlock.totalSize = data.byteLength;
                        tBlock.data = data.slice(offset, offset + currentBlockSize);
                        tBlock.srcAddress = this.localAddress;
                        tBlock.destAddress = this.remoteAddress;
                        let tBlockBA = tBlock.serialize();


                        await this.sendFrame(t.destAddress, tBlockBA);
                        offset += currentBlockSize;
                    }

                    for (let i = 0; i < 100; i++) {
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

                    let allowToResetSession = true;
                    if (aesKeyOriginal.byteLength == 32 && this.aesKey.byteLength == 32) {
                        let aesKeyOriginalView = new DataView(aesKeyOriginal);
                        let aesKeyView = new DataView(this.aesKey);
                        for (let i = 0; i < 32; i++) {
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
            let privateKeyBS64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4T69E5NAQjf8yZDe1spPizbGkgmqYxr+0ry3NIYNkkpfa4GpwP5FFeg8/Zk22SNHqFy9txMkwVfxATLj2tB/BcqqjhUxq85unQlGxAyYatsy5VcxOronqizNjjd37/MEOHW7V3anK0sHes+BGat/2t10tZFWhP+KNF4l0D2SusmZ+iD/C+Yv8UAFtWAk9zpcUY6MnGm0Tv/FCVkiwbaUDwfz29meQnbse24iRxgRPQ7F1TLiLInir4savKD555hPTAEFIjd0Jetv3RUyF4qaRjko8bfe7F0GSXtQtIimu3+5oaroxKxg3W9RFr3BKVmGc1AD2LHNHYSER3L9NhUR1AgMBAAECggEAJWxwnyGCqcnbRmUY9rjC1GuFpWyhrlG0vUBQoXUrk7E8SkIE+rO9kIjfLbVdFCUnEkwQ4k3xt/HNnVS2vckHJaVdxoQbZx/9u/F4WuPTydrSKNOl/1frQwdusMkuiKrinDYXui8e+cLfgJOvdzzeKt9CeSQFSw+ItbNQwpMZk2rnho6iTMPXiiKj6pfec7I2miNUFHQEWt698fFaLzmKc/qSTAmlBQyiiFQNsP1dieMXboV23gLaH4tVwoRsVgM6V6HAyhIbyNHzqGRXJB6uasytnrcSBLb646WepLnskpgBg+VZjBgE3r7PMoJ7raQBViD9Zyz4DVGZbzB315cVwQKBgQDLyE9GyfB4vqgj863puVjlgnhBFmcZops7yI469UuwGd5WQ9tErn9Tx0LrSk8/PQIkOAHwit8F2UNlQEjq1HWOXWjI0wu67okOs8ax8a5gOIistBKfezK08SyIy2HXi9dKU673pasx5vamDhpm3wis3LP3/KLhrw0Wfjhy+bOF0QKBgQDnihtUXWW4MBbn5dMeUFTKefgw/kmxnTc9FyR9YJDBJ0b4vOsi6I0HuuQzOCFS3qXLdmlmkhfGk8089fBWAQ8rlQZUvMl9XyX3T7EEL8kIKUpnAS1o1jzb/ls1RU5735L/ngSzr0V5fT7Da74WSXhRk3esUkZserpLx0JbXtMpZQKBgQCWrGf5dkyoaogV9RHtE49oO1zA+1iF+tX+kR6g90fcUHQ1onyYvtEEV/vhzxLjNi/EKek9OuEGCQus7Kg9gZPeDLDydCFjOQX76e8LGSCOop5j2809QDFQ2lXMW1zfq9UmbtOa5lK7VgOe6iSZVWWrspAa1yBz8COkMvV4Baq4UQKBgCDuQo7QLcxxgoB+7nTsRfL6P/Nv5zlMu/ODXBw85LmkBXMRI3w2iQBlc1lZjVvE8N2sPLdq5djHYrRd4k3JHsg7DMh2hU3Af5zaB7optbTkcoGN6FB1z/gWCBDeh5gUp0qVxeNsdTwfNRMEOufekS9BAw9OMFfzaJWohGaMaQoFAoGBAMuwwMYAhUuMcAHuhzy52/KBYcSLcqigsrrQzgdj3x8X/CZuFvez1ErBbgn+IjVgx3teZfRVzsvblEOo4yrohkMPfmWTgH1AHNSTDeBnPsw3lzrk+DdWDYCiUWkgRr+tEIJF7KMreNHvR5bK7is7UFowd9FcOGnPe8aN/Ww4H+Px"
            let publicKeyBS64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuE+vROTQEI3/MmQ3tbKT4s2xpIJqmMa/tK8tzSGDZJKX2uBqcD+RRXoPP2ZNtkjR6hcvbcTJMFX8QEy49rQfwXKqo4VMavObp0JRsQMmGrbMuVXMTq6J6oszY43d+/zBDh1u1d2pytLB3rPgRmrf9rddLWRVoT/ijReJdA9krrJmfog/wvmL/FABbVgJPc6XFGOjJxptE7/xQlZIsG2lA8H89vZnkJ27HtuIkcYET0OxdUy4iyJ4q+LGryg+eeYT0wBBSI3dCXrb90VMheKmkY5KPG33uxdBkl7ULSIprt/uaGq6MSsYN1vURa9wSlZhnNQA9ixzR2EhEdy/TYVEdQIDAQAB"
            let signature64 = "ezSPgdjI4dXd20xMObVGUFnNuW9WOHfL5Aw07jDFDiwjd3zL+HdPcAyCTmG09YlvIdMbTFWFkGuCJZqcjDDbzU5x64y29xxM7zKOq75nDTiXiOsvKp5uX0/tGWseyajniz+MCbaHhJ4buhwybFXnkYMdKPzL9LrXrOtejbQ/A1OnwN2QrJY7tkCbfBGZ/2o5bxgPZWtl53gGsOXNlsjMw8CWk7i7u1UIT0OKEwKpdgnfPA+QwyOUR4lOv7Tx0Nib20vCp5nIUajMgQsRamDKzp0hZLBTibpXJ/j1vRML4JVp3Eabj5wf01PCNfKJ1Ur3S/WIDSRtdOM1FutIq8Qvjg=="
            let privateKeyBS = this.base64ToArrayBuffer(privateKeyBS64);
            let publicKeyBS = this.base64ToArrayBuffer(publicKeyBS64);
            let signature = this.base64ToArrayBuffer(signature64);
            let privateKeyBSHash = await crypto.subtle.digest('SHA-256', privateKeyBS);
            let publicKeyBSHash = await crypto.subtle.digest('SHA-256', publicKeyBS);
            console.log("privateKeyBSHash", privateKeyBSHash);
            console.log("publicKeyBSHash", publicKeyBSHash);

            let privateKeyForSigning = await window.crypto.subtle.importKey(
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

            let publicKey = await window.crypto.subtle.importKey("spki",
                publicKeyBS,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256"
                },
                true,
                ["verify"]
            );
            console.log("publicKey", publicKey);
            let exportedPublicKey = await window.crypto.subtle.exportKey("spki", publicKey);
            exportedPublicKey = this.arrayBufferToBase64(exportedPublicKey)
            console.log("exportedPublicKey", exportedPublicKey);


            let dataToVerify = new ArrayBuffer(3)
            let dataToVerifyView = new DataView(dataToVerify);
            dataToVerifyView.setUint8(0, 42)
            dataToVerifyView.setUint8(1, 43)
            dataToVerifyView.setUint8(2, 44)

            let hash = await crypto.subtle.digest('SHA-256', dataToVerify);
            //hash = await crypto.subtle.digest('SHA-256', hash);
            hash = dataToVerify;

            let resSign = await window.crypto.subtle.sign(
                {
                    name: "RSA-PSS",
                    saltLength: 32,
                },
                privateKeyForSigning,
                dataToVerify
            );
            console.log("resSign", resSign);

            let res = await window.crypto.subtle.verify(
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
