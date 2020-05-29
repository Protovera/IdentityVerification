const BitID = require("./bitIdentity.js");
const filepay = require("filepay");
const bsv = filepay.bsv;

var privateKey = "your payment pivate key"; //please replace with your key
var idPrivateKey = "your identity private key"; //please replace with your key

console.log(BitID);
(async () => {
	var data1 = ["test", "good"];
	let script1 = filepay.data2script(data1).toHex();
	let config = {
		pay: {
			key: bsv.PrivateKey.fromWIF(privateKey),
			feeb: 0.5,
			to: [
				{ protocol: "bitIdentity", value: { privateKey: idPrivateKey } },
				{ data: ["1", "ddd", "test"], value: 0 },
				{ protocol: "bitIdentity", value: { privateKey: idPrivateKey } },
				{ script: script1, value: 0 },
				{ address: "1PuMeZswjsAM7DFHMSdmAGfQ8sGvEctiF5", value: 1000 },
			],
		},
	};
	const rawtx = await BitID.gentx(config);
	console.log(BitID.verifyID(rawtx));
})();
