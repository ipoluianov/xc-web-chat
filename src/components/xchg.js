var xchg_utils = new makeXchg();
export default xchg_utils;

import base32 from "./base32";
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
            var bytes = new Uint8Array(buffer);
            var len = bytes.byteLength;
            for (var i = 0; i < len; i++) {
                binaryString += String.fromCharCode(bytes[i]);
            }
            return binaryString;
        },

        makeXchgrReadRequest(address) {
            address = address.replaceAll("#", "");
            var myBuffer = new ArrayBuffer(46);
            var view1 = new DataView(myBuffer);
            view1.setBigUint64(0, BigInt(0)); // AfterId
            view1.setBigUint64(8, BigInt(1024 * 1024)); // MaxSize
            var addressBS = this.addressToAddressBS(address);
            console.log(addressBS);
            var view2 = new DataView(addressBS);
            for (var i = 0; i < 30; i++) {
                view1.setInt8(i + 16, view2.getInt8(i));
            }
            var ww = this.arrayBufferToBase64(myBuffer)
            return ww
        },

        addressToAddressBS(address) {
            var addressBS = base32.decode(address)
            return this.binaryStringToArrayBuffer(addressBS);
        },

        async requestXchgrRead(address) {
            try {
                var frame = this.makeXchgrReadRequest(address);
                const formData = new FormData();
                formData.append('d', frame);
                const response = await axios.post("http://localhost:8084/api/r", formData, {
                    headers: formData.headers
                },);
                console.log("RESULT", response.data);
                this.ttt = response.data;
            } catch (ex) {
                console.log(ex);
            }
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
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            var res = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    length: 256,
                    iv: iv,
                },
                aesKey,
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
            var bs = new Uint8Array(arrayBufferEncrypted);
            var iv = bs.subarray(0, 12);
            var ch = bs.subarray(12);
            var res = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    length: 256,
                    iv: iv,
                },
                aesKey,
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
            zip.file("d", baData);
            var content = await zip.generateAsync({type:"arrayBuffer"});
            return content
        },

        async unpack(baZIP) {
            var baZIP = this.base64ToArrayBuffer(zip64);
            var zip = await JSZip.loadAsync(baZIP);
            var content =  await zip.files["d"].async('arrayBuffer')
            return content;
        },

        testData() {
            var buf = new ArrayBuffer(2);
            var v = new DataView(buf);
            v.setInt8(0, 42);
            v.setInt8(1, 43);
            return buf;
        },

        async test() {
            var content = await this.unpack();
            console.log(content)
            var content64 = this.arrayBufferToBase64(content);
            console.log(content64)
        },
    }
}
