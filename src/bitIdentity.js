var isBrowser =
	isBrowser ||
	new Function("try {return this===window;}catch(e){ return false;}");

var filepay;
var bsv;
var g_isBrowser = isBrowser();

const bitId_Protocol = "14kxqYv3emHGwf8m6YgSYLQkGCvn9Qrgr9";
const bitId_Protocol1 = "14kxqYv3emHGwf8m6YgSYLQkGCvn9Qrgr91";

const PLACEHOLDER_LEN = 150;
const placeholder = " ".repeat(PLACEHOLDER_LEN);
const placeholder_buf = Buffer.alloc(70,' ');

var filepayKey = "";
let log = console.log;

export default class BitID {
	static littleEndian(strHex) {
		if (strHex.length % 2 !== 0) {
			strHex = "0" + strHex;
		}
		let strRet = "";
		for (let c = strHex.length - 2; c >= 0; c -= 2) {
			let by = strHex.substr(c, 2);
			log(by);
			strRet += by;
		}
		return strRet;
	}
	static loadScript(url, callback) {
		var script = document.createElement("script");
		script.type = "text/javascript";

		if (script.readyState) {
			//IE
			script.onreadystatechange = function () {
				if (
					script.readyState == "loaded" ||
					script.readyState == "complete"
				) {
					script.onreadystatechange = null;
					if (callback) callback();
				}
			};
		} else {
			//Others
			script.onload = function () {
				if (callback) callback();
			};
		}

		script.src = url;
		document.getElementsByTagName("head")[0].appendChild(script);
	}
	static config(options) {
		if ((options.debug == false)) {
			log = (msg) => {};
		}
		filepayKey = options.filepayKey;
	}

	static gentx(option) {
		
		return new Promise((resolve, reject) => {
			option.pay.to.forEach((out) => {
				if ( out.protocol && (out.protocol.toLowerCase() == "bitidentity") ) {
					const pk = bsv.PrivateKey.fromWIF(out.value.privateKey);
					const pubKey = bsv.PublicKey.fromPrivateKey(pk);
					out["data"] = [
						bitId_Protocol,
						pubKey.toString(),
						placeholder,
					];
					out["pvalue"] = out.value;
					out.value = 0;
				}
				if ( out.protocol && (out.protocol.toLowerCase() == "bitid") ) {	
					const pk = bsv.PrivateKey.fromWIF(out.value.privateKey);
					const pubKey = bsv.PublicKey.fromPrivateKey(pk);
					out["data"] = [
						bitId_Protocol1,
						pubKey.toBuffer(),
						placeholder_buf,
					];
					out["pvalue"] = out.value;
					out.value = 0;
				}
			});
			log(option.pay.to);
			option.api_key = filepayKey;
			filepay.build(option, (e, tx) => {
				if (tx) {
					log("temp rawtx=", tx.toString());
					let data2sign = this.genData2sign(tx);
					//log("data2sign=" + data2sign);
					var hash = bsv.crypto.Hash.sha256(
						bsv.deps.Buffer.from(data2sign)
					);
					log("temp hash=" + hash.toString("hex"));
					log("temp fee=",tx.getFee());
					//option.pay.fee = tx.getFee();
					//delete option.pay.feeb;
					option.pay.to.forEach((out) => {
						if ( out.protocol && out.protocol.toLowerCase() == "bitidentity" ) {
							const pKey = bsv.PrivateKey.fromWIF(
								out.pvalue.privateKey
							);
							var sig = bsv.crypto.ECDSA.sign(hash, pKey);
							const sig_str = sig.toString();

							out.data[2] = sig_str.concat(
								" ".repeat(PLACEHOLDER_LEN - sig_str.length)
							);
							log("signature=", sig_str);
							delete out.protocol;
							delete out.pvalue;
						}
						if ( out.protocol && out.protocol.toLowerCase() == "bitid" ) {
							const pKey = bsv.PrivateKey.fromWIF(
								out.pvalue.privateKey
							);
							var sig = bsv.crypto.ECDSA.sign(hash, pKey);
							const sig_buf = sig.toBuffer();
							//sig_buf.copy(placeholder_buf);
							out.data[2] = sig_buf;
							//log("signature=", placeholder_buf.toString('hex'));
							delete out.protocol;
							delete out.pvalue;
						}
					});
					log(option.pay);
					filepay.build(option, (e, tx) => {
						if (tx) {
							//log("data2sign111=" + this.genData2sign(tx));
							log("rawtx=" + tx.toString());
							//tx.fee(option.pay.fee);
							log("fee=" + tx.getFee());
							resolve(tx.toString());
						} else {
							reject(e);
						}
					});
				} else {
					reject(e);
				}
			});
		});
	}

	static verifyID(rawtx) {
		

		const tx = bsv.Transaction(rawtx);
		//log(tx);
		const data2sign = this.genData2sign(tx);
		//log("data2sign====="+data2sign);
		const bids = this.getBitID(tx);
		log(bids);
		var hash = bsv.crypto.Hash.sha256(bsv.deps.Buffer.from(data2sign));
		log("verify hash=",hash.toString('hex'));
		//	log("sig="+sig.sig.toString());
		//	log("pubkey="+sig.publicKey.toString('hex'));
		if (bids.length > 0) {
			for (var i = 0; i < bids.length; i++) {
				const bid = bids[i];
				var verified = bsv.crypto.ECDSA.verify(
					hash,
					bid.sig,
					bid.publicKey
				);
				if (!verified) return false;
			}
			return true;
		}
		return false;
	}

	static getBitID(tx) {
		

		if (typeof tx === "string") {
			tx = bsv.Transaction(tx);
		}
		let ret = [];
		let pos = 0;
		tx.outputs.forEach((out) => {
			const sc = new bsv.Script.fromBuffer(out._scriptBuffer);
			const sc_len = sc.chunks.length;
			if (sc.chunks[1].opcodenum == 106) {
				const str2 = sc.chunks[2].buf.toString();
				if (str2 == bitId_Protocol || str2 == bitId_Protocol1) {
					const bHex = (str2 == bitId_Protocol1);
					const pk = bsv.PublicKey.fromString(
						sc.chunks[3].buf.toString(bHex?'hex':'utf8')
					);
					const sig = bsv.crypto.Signature.fromString(
						sc.chunks[4].buf.toString(bHex?'hex':'utf8')
					);
					ret.push({ publicKey: pk, sig: sig, pos: pos });
				}
			}
			pos++;
		});
		return ret;
	}
	static genData2sign(tx) {
		

		let data2sign = "";
		//log(tx);
		tx.inputs.forEach((inp) => {
			data2sign += inp.prevTxId.toString("hex") + inp.outputIndex;
		});
		tx.outputs.forEach((out) => {
			const sc = new bsv.Script.fromBuffer(out._scriptBuffer);
			const sc_len = sc.chunks.length;
			if (sc.chunks[1].opcodenum == 106) {
				const str2 = sc.chunks[2].buf.toString();
				if (str2 == bitId_Protocol || str2 == bitId_Protocol1) {
					const bHex = (str2 == bitId_Protocol1);
					log(
						"found bitID. PublicKey=" + sc.chunks[3].buf.toString(bHex?'hex':'utf8')
					);
					data2sign += sc.chunks[3].buf.toString(bHex?'hex':'utf8') + out._satoshis; //public key
				} else {
					data2sign += sc.toHex() + out._satoshis;
				}
			} else {
				data2sign += sc.toHex() + out._satoshis;
			}
		});
		log("data2sign=" + data2sign);
		return data2sign;
	}

	static genScriptFromBitbus(out) {
		

		//TODO: figure out how to gen script without workaround;
		let data = "";
		for (var i = 0; i < out.len; i++) {
			if (out["s" + i]) {
				let opcodenum = 0;
				const len = bsv.deps.Buffer.from(out["b" + i], "base64").length;

				if (len >= 0 && len < bsv.Opcode.OP_PUSHDATA1) {
					opcodenum = 0;
				} else if (len < Math.pow(2, 8)) {
					opcodenum = bsv.Opcode.OP_PUSHDATA1;
				} else if (len < Math.pow(2, 16)) {
					opcodenum = bsv.Opcode.OP_PUSHDATA2;
				} else if (len < Math.pow(2, 32)) {
					opcodenum = bsv.Opcode.OP_PUSHDATA4;
				} else {
					throw new Error("You can't push that much data");
				}

				if (opcodenum) {
					opcodenum = opcodenum.toString(16);
					data += opcodenum;
				}
				let hex = len.toString(16);
				//if (hex.length < 2) hex = "0" + hex;
				hex = this.littleEndian(hex);

				data += hex + out["h" + i];
			} else if (out["o" + i]) {
				let hex = bsv.Opcode.fromString(out["o" + i]).toHex();
				if (hex.length < 2) hex = "0" + hex;
				data += hex;
			}
		}
		return data;
	}

	static genData2signFromBitbus(bitbusRtx) {
		

		let data2sign = "";
		bitbusRtx.in.forEach((inp) => {
			data2sign += inp.e.h + inp.e.i;
		});
		bitbusRtx.out.forEach((out) => {
			if (out.o1 && out.o1 == "OP_RETURN") {
				if (out.s2 && (out.s2 == bitId_Protocol || out.s2==bitId_Protocol1) ) {
					const str = (out.s2==bitId_Protocol1) ? out.h3:out.s3;
					log("found bitID. PublicKey=" + str);
					data2sign += str + out.e.v; //public key
				} else {
					// data2sign += sc.toHex();
					data2sign += this.genScriptFromBitbus(out) + out.e.v;
				}
			} else {
				// data2sign += sc.toHex() + out._satoshis;
				data2sign += this.genScriptFromBitbus(out) + out.e.v;
			}
		});

		log("bitbus data2sign=" + data2sign);
		return data2sign;
	}

	static getBitIDFromBitbus(bitbusRtx) {
		

		let ret = [];
		let pos = 0;
		bitbusRtx.out.forEach((out) => {
			if (out.o1 == "OP_RETURN" && (out.s2 == bitId_Protocol || out.s2==bitId_Protocol1)) {
				const bHex = (out.s2==bitId_Protocol1);
				const sPubkey = bHex?out.h3:out.s3;
				const sSig = bHex?out.h4:out.s4;
				const pk = filepay.bsv.PublicKey.fromString(sPubkey);
				const sig = filepay.bsv.crypto.Signature.fromString(sSig);
				ret.push({ publicKey: pk, sig: sig, pos: pos });
			}
			pos++;
		});
		return ret;
	}

	static verifyIDFromBitbus(bitbusRtx) {
		

		//log(JSON.stringify(bitbusRtx));
		const data2sign = this.genData2signFromBitbus(bitbusRtx);
		const bids = this.getBitIDFromBitbus(bitbusRtx);
		log(bids);
		let hash = null;
		if (isBrowser() == false) {
			hash = filepay.bsv.crypto.Hash.sha256(
				bsv.deps.Buffer.from(data2sign)
			);
		} else {
			hash = filepay.bsv.crypto.Hash.sha256(
				bsv.deps.Buffer.from(data2sign)
			);
		}
		if (bids && bids.length > 0) {
			for (let i = 0; i < bids.length; i++) {
				let bid = bids[i];
				var verified = filepay.bsv.crypto.ECDSA.verify(
					hash,
					bid.sig,
					bid.publicKey
				);
				if (!verified) return false;
			}
			return true;
		}
		// bids.forEach((bid) => {
		// 	var verified = filepay.bsv.crypto.ECDSA.verify(hash, bid.sig, bid.publicKey);
		// 	if (!verified) return false;
		// });
		return false;
	}
}

if (g_isBrowser) {
	if(!window.filepay){
		BitID.loadScript(
			"https://unpkg.com/filepay@latest/dist/filepay.min.js",
			() => {
				filepay = window.filepay;
				bsv = filepay.bsv;
			}
		);
	}else{
		filepay = window.filepay;
		bsv = filepay.bsv;
	}
} else {
	if (!filepay) {
		filepay = require("filepay");
		bsv = filepay.bsv;
	}
}

if (!g_isBrowser) {
	module.exports = BitID;
}
