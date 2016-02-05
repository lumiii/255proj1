var lib = function() {
    return {
       /* Input: password (String) and salt (String)
        * Output: promise, value: 512-bit hash/raw key (ArrayBuffer)
        */
       balloonHash: function(password, salt) {
            return new Promise(function(resolve, reject) {
                if (typeof (Worker) === "undefined") {
                    reject("ERROR: Your browser does not support JS workers.");
                }
                var w = new Worker ("balloon.js");
                w.onmessage = function(a) {resolve(a.data.hash);};
                var params = {
                    password: password,
                    salt: salt,
                    time_cost: 3,
                    space_cost: 1024*16
                };
                w.postMessage(params);
            });
        },
        /* Input: 256-bit raw key (ArrayBuffer)
         * Output: promise, value: key usable by decrypt function (CryptoKey)
         */
        importKey: function(raw_key) {
            return window.crypto.subtle.importKey(
                "raw", // The format of the key
                raw_key, // The raw bytes of the key
                "AES-GCM", // The algorithm
                false, // Whether the key is extractable using exportKey
                ["encrypt", "decrypt"] // Valid operations using this key
            );
        },
        /* Input: key (CryptoKey), data (ArrayBuffer), and IV (UInt8Array)
         * Output: promise, value: decrypted data (ArrayBuffer)
         * Source: Adapted from https://github.com/diafygi/webcrypto-examples
         */
        decrypt: function(key, data, iv) {
            return window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv, //The initialization vector you used to encrypt
                    tagLength: 128 //The tagLength you used to encrypt (if any)
                },
                key, //from generateKey or importKey above
                data //ArrayBuffer of the data
            );
        },
        /* Input: data (ArrayBuffer)
         * Output: promise, value: 256-bit hash (ArrayBuffer)
         */
        sha256Hash: function(data) {
            return window.crypto.subtle.digest({name: "SHA-256"}, data);
        },
        /* Input: hex representation of bytes (String)
         * Output: buffer of bytes (ArrayBuffer)
         * Source: Adapted from crypto-js
         */
        hexToArrayBuffer: function(hex) {
            for (var bytes = [], c = 0; c < hex.length; c += 2) {
                bytes.push(parseInt(hex.substr(c, 2), 16));
            }
            return new Uint8Array(bytes).buffer;
        },
        /* Input: buffer of bytes (ArrayBuffer)
         * Output: hex representation of bytes (String)
         * Source: Adapted from crypto-js
         */
        arrayBufferToHex: function(buf) {
            var view = new DataView(buf);
            for (var str = "", i = 0; i < buf.byteLength; i++) {
                str = str + ("0" + view.getUint8(i).toString(16)).slice(-2);
            }
            return str;
        },

        /**********************************************************
         *                                                        *
         *   You should not need any functions below this point.  *
         *                                                        *
         **********************************************************/

        /* Input: none
         * Output: 12 bytes of randomness (UInt8Array)
         * Source: Adapted from https://github.com/diafygi/webcrypto-examples
         */
        generateIV: function() {
            return window.crypto.getRandomValues(new Uint8Array(12));
        },
        /* Input: key (CryptoKey), data (ArrayBuffer), and IV (UInt8Array)
         * Output: promise, value: encrypted data (ArrayBuffer)
         * Source: Adapted from https://github.com/diafygi/webcrypto-examples
         */
        encrypt: function(key, data, iv) {
            return window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    //Don't re-use initialization vectors!
                    //Always generate a new iv every time your encrypt!
                    //Recommended to use 12 bytes length
                    iv: iv,

                    //Tag length (optional)
                    tagLength: 128 //can be 32, 64, 96, 104, 112, 120 or 128 (default)
                },
                key, //from generateKey or importKey above
                data //ArrayBuffer of data you want to encrypt
            );
        },
        /* Input: URL (String)
         * Output: promise, value: the downloaded data (ArrayBuffer)
         */
        getData: function(url) {
            return fetch(url, {mode: 'no-cors'}).then(function(resp) {
                console.log("Downloaded data with status", resp.status);
                return resp.arrayBuffer();
            });
        }
    };
}();
