const { workerData, parentPort } = require("worker_threads");
const forge = require("node-forge");

try {
  const key = forge.pki.privateKeyFromPem(forge.util.decode64(workerData.privatekey));
  const content = workerData.content;
  Object.keys(content).map((entry) => {
    if (content[entry] !== null) {
      if (Array.isArray(content[entry])) {
        content[entry].map((v, i) => {
          content[entry][i] = forge.util.decode64(key.decrypt(forge.util.decode64(content[entry][i]), "RSA-OAEP", { md: forge.md.sha512.create() }));
        });
      } else {
        content[entry] = forge.util.decode64(key.decrypt(forge.util.decode64(content[entry]), "RSA-OAEP", { md: forge.md.sha512.create() }));
      }
    }
  });
  parentPort.postMessage(content);
} catch (err) {
  throw new Error();
}
