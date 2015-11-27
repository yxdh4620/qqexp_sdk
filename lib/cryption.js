var url = require("url");
var crypto = require('crypto');

var Cryption = {
    IgnoredSigName: ["appsig", "reqsig", "paysig"],
    /** 生成请求或响应数据的签名
     *
     * @param uri 请求的Url
     * @param method 请求的方式，如GET,POST等
     * @param queryMap 查询参数对象
     * @param appKey 应用密钥
     * @returns {*} 返回请求或响应签名
     * @constructor
     */
    GetDataSig: function (uri, method, queryMap, appKey) {
        for (var i = 0; i < this.IgnoredSigName.length; i++) {
            if (queryMap.hasOwnProperty(this.IgnoredSigName[i]))
                delete queryMap[this.IgnoredSigName[i]];
        }

        var pathname = url.parse(uri).pathname;
        //console.log(uri,",",pathname);
        var path = this.UrlEncode(pathname, 1);

        var paras = [];
        var keys = Object.keys(queryMap).sort();
        keys.forEach(function (key) {
            paras.push(key + "=" + queryMap[key]);
        });
        paras = paras.join("&");
        paras = this.UrlEncode(paras, 1);

        var srcUrl = method + "&" + path + "&" + paras;
        var srcSigKey = appKey + "&";
        console.log("签名中间数据(NodeJS)：" + srcUrl);        
        var dataSig = this.GetSig(srcUrl, srcSigKey);
        return dataSig;
    },
    /** 获取应用签名
     *
     * @param appId 应用Id
     * @param time  时间戳
     * @param nonce 随机串
     * @param appKey 应用密钥
     * @param dataKey 数据加密密钥
     * @returns {*} 返回应用签名
     * @constructor
     */
    GetAppSig: function (appId, time, nonce, appKey, dataKey) {
        var src = appId + "_" + time + "_" + nonce;
        var cipher = this.GetCipherData(src, dataKey);
        appKey += "&";
        var appsig = this.GetSig(cipher, appKey);
        return appsig;
    },
    /** 获取签名
     *
     * @param rawData 需签名的数据
     * @param appKey 密钥
     * @returns {*} 返回数据的签名
     * @constructor
     */
    GetSig: function (rawData, appKey) {
        var cipher = crypto.createHmac('SHA1', appKey);
        cipher.update(rawData);
        cipher = cipher.digest('binary');
        var sig = new Buffer(cipher, "binary").toString("base64");
        sig = this.UrlEncode(sig);
        return sig;
    },
    /** 获取加密密文
     *
     * @param rawData 需加密的明文数据
     * @param key 密钥
     * @returns {*|string} 返回加密密文的Base64及this.UrlEncode后的串
     * @constructor
     */
    GetCipherData: function (rawData, key) {
        var cipher = this.EncryptAES(rawData, key, null, null, "binary");
        cipher = new Buffer(cipher, "binary").toString("base64");
        cipher = this.UrlEncode(cipher);
        return cipher;
    },
    /** 获取明文
     *
     * @param cipherData 需解密的明文
     * @param key 密钥
     * @returns {*|string} 返回解密后的明文数据（utf8格式）
     * @constructor
     */
    GetPlainData: function (cipherData, key) {
        var plain = this.UrlDecode(cipherData);
        plain = new Buffer(plain, "base64");
        plain = this.DecryptAES(plain, key, null, null, "utf8");
        return plain;
    },
    /** AES加密函数
     *
     * @param plainText 明文
     * @param key 密钥
     * @param algorithm 算法，默认 aes-128-ecb
     * @param inputEncoding 输入编码，默认 utf8 ，可选值： "utf8", "ascii", "binary"
     * @param outputEncoding 输出编码 默认 base64，可选值："binary", "hex", "base64"
     * @returns {string} 返回加密密文
     * @constructor
     */
    EncryptAES: function (plainText, key, algorithm, inputEncoding, outputEncoding) {
        algorithm = algorithm || "aes-128-ecb";
        inputEncoding = inputEncoding || "utf8";
        outputEncoding = outputEncoding || "base64";

        var blockSize = 16, iv = "";
        var bytesLen = Buffer.byteLength(plainText, "utf8");
        var padding = blockSize - bytesLen % blockSize; //plainText.length
        while (padding-- > 0) {
            plainText += '\0';
        }

        var cipher = crypto.createCipheriv(algorithm, key, iv);
        cipher.setAutoPadding(false);

        var cipherChunks = [];
        cipherChunks.push(cipher.update(plainText, inputEncoding, outputEncoding));

        var cipherBinary;
        var last = cipher.final(outputEncoding);
        if (last.length > 0) {
            cipherChunks.push(last);
            cipherBinary = Buffer.concat(cipherChunks, cipherChunks.length); //连接多个Buffer
        } else {
            cipherBinary = cipherChunks[0];
        }
        return cipherBinary;
    },
    /** AES解密函数
     *
     * @param cipherChunks 密文chunk数组
     * @param key 密钥
     * @param algorithm 算法，默认 aes-128-ecb
     * @param inputEncoding 输入编码，默认 utf8 ，可选值： "utf8", "ascii", "binary"
     * @param outputEncoding 输出编码 默认 base64，可选值："binary", "hex", "base64"
     * @returns {string} 返回解密明文
     * @constructor
     */
    DecryptAES: function (cipherText, key, algorithm, inputEncoding, outputEncoding) {
        algorithm = algorithm || "aes-128-ecb";
        inputEncoding = inputEncoding || "utf8";
        outputEncoding = outputEncoding || "base64";
        var iv = "";
        var decipher = crypto.createDecipheriv(algorithm, key, iv);
        decipher.setAutoPadding(false);

        var plainChunks = [];
        plainChunks.push(decipher.update(cipherText, outputEncoding, inputEncoding));
        plainChunks.push(decipher.final(inputEncoding));
        var plaintext = plainChunks.join('');

        //去掉结尾的结束符
        var index = plaintext.indexOf('\0');
        if (index > -1)
            plaintext = plaintext.substring(0, index);

        //资源清理
        plainChunks.length = 0;
        plainChunks = undefined;

        return plaintext;
    },
    /** 生成HMac哈希验证码
     *
     * @param data 生成HMac的源数据
     * @param key 密钥
     * @returns {*} 返回生成的HMac-SHA1验证码
     * @constructor
     */
    EncodeHmac: function (data, key) {
        var cipher = crypto.createHmac('SHA1', key);
        cipher.update(data);
        cipher = cipher.digest('binary');
        return cipher;
    },
    UrlEncode: function (rawData, isSignSrc) {
        var result = encodeURIComponent(rawData);
        result = result.replace(/!/g, "%21")
                .replace(/'/g, "%27")
                .replace(/\(/g, "%28")
                .replace(/\)/g, "%29")
                .replace(/\*/g, "%2A");

        if (isSignSrc)
            result = result.replace(/~/g, "%7E");
        return result;
    },
    UrlDecode: function (encodedData) {
        var result = decodeURIComponent(encodedData);
        return result;
    }
};

module.exports.cryption = Cryption;
