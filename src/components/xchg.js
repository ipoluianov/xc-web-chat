var xchg = new makeXchg();
export default xchg;

import base32 from "./base32";
import axios from "axios";
import JSZip from "jszip";
import makeXPeer from "./xpeer";

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
            var addressBS = base32.decode(address)
            return this.binaryStringToArrayBuffer(addressBS);
        },

        addressBSToAddress32(addressBS) {
            var address32 = base32.encode(this.arrayBufferToBinaryString(addressBS))
            return "#" + address32.toLowerCase();
        },

        address32ToAddressBS(address32) {
            if (address32 === undefined) {
                return new ArrayBuffer(30);
            }
            address32 = address32.replaceAll("#", "")
            var addressBinaryString = base32.decode(address32)
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
            var publicKey = window.crypto.subtle.importKey("spki",
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
                    modulusLength: 4096,
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
            var content = await zip.generateAsync({type:"arrayBuffer"});
            return content
        },

        async unpack(baZIP) {
            //var baZIP = this.base64ToArrayBuffer(zip64);
            var zip = await JSZip.loadAsync(baZIP);
            var content =  await zip.files["data"].async('arrayBuffer')
            return content;
        },

        makeTransaction() {
            var t = {
                length:0,
                crc:0,
                frameType:0,
                transactionId:0n,
                sessionId:0n,
                offset:0,
                totalSize:0,
                srcAddress:"",
                destAddress:"",
                data:new ArrayBuffer(0),

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

        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },

        testData() {
            var buf = new ArrayBuffer(2);
            var v = new DataView(buf);
            v.setInt8(0, 42);
            v.setInt8(1, 43);
            return buf;
        },

        async test() {
        },
    }
}
