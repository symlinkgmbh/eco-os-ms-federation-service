/** 
* Copyright 2018-2019 Symlink GmbH 
* 
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at 
*  
*     http://www.apache.org/licenses/LICENSE-2.0 
* 
* Unless required by applicable law or agreed to in writing, software 
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License. 
* 
*/ 

import { IFederationEncryptor } from "./IFederationEncryptor";
import * as forge from "node-forge";
import { injectable } from "inversify";

@injectable()
class FederationEncryptor implements IFederationEncryptor {
  public async encryptBody(publicKeyPem: string, body: any): Promise<object> {
    const key: any = forge.pki.publicKeyFromPem(forge.util.decode64(publicKeyPem));

    Object.keys(body).map((entry: any) => {
      body[entry] = forge.util.encode64(key.encrypt(forge.util.encode64(body[entry]), "RSA-OAEP", { md: forge.md.sha512.create() }));
    });
    return body;
  }
}

export { FederationEncryptor };
