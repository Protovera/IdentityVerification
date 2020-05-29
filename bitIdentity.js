
const filepay = require("filepay");
const bsv = filepay.bsv;



const bitId_Protocol = "14kxqYv3emHGwf8m6YgSYLQkGCvn9Qrgr9";

const PLACEHOLDER_LEN = 150;
const placeholder = " ".repeat(PLACEHOLDER_LEN);

class BitID{
static gentx (config) {
	return new Promise((resolve, reject) => {
		config.pay.to.forEach((out) => {
			if (out.protocol && out.protocol == "bitIdentity") {
				const pk = bsv.PrivateKey.fromWIF(out.value.privateKey);
				const pubKey = bsv.PublicKey.fromPrivateKey(pk);
				out["data"] = [bitId_Protocol, pubKey.toString(), placeholder];
				out["pvalue"] = out.value;
				out.value = 0;
			}
		});
		console.log(config.pay.to);
		filepay.build(config, (e, tx) => {
			if (tx) {
				console.log("rawtx1=", tx.toString());
				let data2sign = BitID.genData2sign(tx);
				console.log("data2sign=" + data2sign);
				var hash = bsv.crypto.Hash.sha256(Buffer.from(data2sign));
				console.log("hash=" + hash.toString("hex"));
				config.pay.to.forEach((out) => {
					if (out.protocol && out.protocol == "bitIdentity") {
						const pKey = bsv.PrivateKey.fromWIF(
							out.pvalue.privateKey
						);
						var sig = bsv.crypto.ECDSA.sign(hash, pKey);
						const sig_str = sig.toString();

						out.data[2] = sig_str.concat(
							" ".repeat(PLACEHOLDER_LEN - sig_str.length)
						);
						console.log("signature=" + sig_str);
						delete out.protocol;
						delete out.pvalue;
					}
				});
				console.log(config.pay.to);
				filepay.build(config, (e, tx) => {
					if (tx) {
						console.log("data2sign111=" + BitID.genData2sign(tx));
						console.log("rawtx=" + tx.toString());
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
	//console.log(tx);
	const data2sign = BitID.genData2sign(tx);
	//console.log("data2sign====="+data2sign);
	const bids = BitID.getBitId(tx);
	console.log(bids);
	var hash = bsv.crypto.Hash.sha256(Buffer.from(data2sign));
	//	console.log("hash="+hash.toString('hex'));
	//	console.log("sig="+sig.sig.toString());
	//	console.log("pubkey="+sig.publicKey.toString('hex'));
	bids.forEach((bid) => {
		var verified = bsv.crypto.ECDSA.verify(hash, bid.sig, bid.publicKey);
		if (!verified) return false;
	});
	return true;
}

static getBitId(tx) {
	let ret = [];
	tx.outputs.forEach((out) => {
		const sc = new bsv.Script.fromBuffer(out._scriptBuffer);
		const sc_len = sc.chunks.length;
		if (sc.chunks[1].opcodenum == 106) {
			if (sc.chunks[2].buf.toString() == bitId_Protocol) {
				const pk = bsv.PublicKey.fromString(
					sc.chunks[3].buf.toString()
				);
				const sig = bsv.crypto.Signature.fromString(
					sc.chunks[4].buf.toString()
				);
				ret.push({ publicKey: pk, sig: sig });
			}
		}
	});
	return ret;
}
static genData2sign(tx) {
	let data2sign = "";
	//console.log(tx);
	tx.inputs.forEach((inp) => {
		data2sign += inp.prevTxId.toString("hex") + inp.outputIndex;
	});
	tx.outputs.forEach((out) => {
		const sc = new bsv.Script.fromBuffer(out._scriptBuffer);
		const sc_len = sc.chunks.length;
		if (sc.chunks[1].opcodenum == 106) {
			if (sc.chunks[2].buf.toString() == bitId_Protocol) {
				console.log(
					"found bitID. PublicKey=" + sc.chunks[3].buf.toString()
				);
				data2sign += sc.chunks[3].buf.toString(); //public key
			} else {
				data2sign += sc.toHex();
			}
		} else {
			data2sign += sc.toHex() + out._satoshis;
		}
	});
	return data2sign;
}
}

module.exports = BitID;
