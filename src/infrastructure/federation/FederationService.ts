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

import { IFederationService } from "./IFederationService";
import dns from "dns";
import { injectable, inject } from "inversify";
import { injectConfigClient, injectLicenseClient } from "@symlinkde/eco-os-pk-core";
import { MsConf, PkCore, MsFederation } from "@symlinkde/eco-os-pk-models";
import { Log, LogLevel } from "@symlinkde/eco-os-pk-log";
import Axios, { AxiosResponse } from "axios";
import { CustomRestError } from "@symlinkde/eco-os-pk-api";
import { IFederationEncryptor } from "./IFederationEncryptor";
import { FEDERATIONTYPES } from "./FederationTypes";
import { CryptionUtils } from "@symlinkde/eco-os-pk-crypt";
import { IFederationStorage } from "./IFederationStorage";

@injectLicenseClient
@injectConfigClient
@injectable()
export class FederationService implements IFederationService {
  private configClient!: PkCore.IEcoConfigClient;
  private licenseClient!: PkCore.IEcoLicenseClient;

  private publicFederationHost!: MsConf.IFederationConfig;
  private licenseChecksum!: string;

  private encryptor: IFederationEncryptor;
  private storage: IFederationStorage;

  public constructor(@inject(FEDERATIONTYPES.IFederationEncryptor) encryptor: IFederationEncryptor, @inject(FEDERATIONTYPES.IFederationStorage) storage: IFederationStorage) {
    this.encryptor = encryptor;
    this.storage = storage;
  }

  public async resolve2ndLock(domain: string): Promise<dns.SrvRecord[] | null> {
    return new Promise((resolve) => {
      dns.resolveSrv(`_2ndlock._tcp.${domain}`, (err, res) => {
        if (err) {
          resolve(null);
        }
        resolve(res);
      });
    });
  }

  public async resolveRemoteUserKeys(email: string): Promise<any> {
    const domain = email.split("@")[1];
    Log.log(`prepare federation for ${domain}`, LogLevel.info);
    const federationObject: any = await this.processFederationFromPublicFederationService(domain);
    // tslint:disable-next-line:forin
    for (const index in federationObject) {
      if (federationObject[index].publickey === undefined || federationObject[index].publickey === "") {
        throw new CustomRestError(
          {
            code: 400,
            message: "federation not possible due missing public key from receipient service",
          },
          400,
        );
      }

      if (federationObject[index].srv.length < 1) {
        throw new CustomRestError(
          {
            code: 400,
            message: "federation not possible due missing dns srv entry for 2ndLock in target domain",
          },
          400,
        );
      }

      const result = await this.federationRequest(federationObject[index].publickey, email, domain, "localhost:9000");
      // await this.federationRequest(federationObject[index].publickey, email, domain, federationObject[index].srv[0].name);
      return result.data;
    }
  }

  public async processFederationFromPublicFederationService(domain: string): Promise<MsFederation.IFederationStorageObject[] | MsFederation.IFederationStorageObject> {
    const storedStorageObject = await this.storage.get(domain);
    if (storedStorageObject.length === 0) {
      const result = await this.loadFederationRemoteInformation(domain);
      const storageObject = await this.parseFederationPublicResponse(result);
      // tslint:disable-next-line:forin
      for (const index in storageObject) {
        await this.storage.set(domain, storageObject[index]);
      }
      return storageObject;
    } else {
      return storedStorageObject;
    }
  }

  private async parseFederationPublicResponse(response: any): Promise<Array<MsFederation.IFederationStorageObject>> {
    const parsedResult: Array<MsFederation.IFederationStorageObject> = [];
    for (const index in response.data) {
      // tslint:disable-next-line: forin
      for (const dIndex in response.data[index]) {
        const dnsLookupResult = await this.resolve2ndLock(response.data[index][dIndex].domain);
        if (dnsLookupResult !== null) {
          await parsedResult.push({
            domain: response.data[index][dIndex].domain,
            created: String(new Date().getTime()),
            publickey: response.data[index][dIndex].publicKey,
            srv: dnsLookupResult,
          });
        }
      }
    }

    return parsedResult;
  }
  private async loadFederationHost(): Promise<MsConf.IFederationConfig> {
    if (!this.publicFederationHost) {
      const loadConf = await this.configClient.get("federation");
      this.publicFederationHost = <MsConf.IFederationConfig>Object(loadConf.data.federation);
    }

    return this.publicFederationHost;
  }

  private async loadLicenseChecksum(): Promise<string> {
    if (!this.licenseChecksum) {
      const result = await this.licenseClient.getChecksumFromLicense();
      this.licenseChecksum = result.data.checksum;
    }

    return this.licenseChecksum;
  }

  private async loadPublicKeyFromFederationService(): Promise<string> {
    try {
      const checksum = await this.loadLicenseChecksum();
      const host = await this.loadFederationHost();
      const result = await Axios.get(`${host.publicFederationSerivce}/api/v1/publickey`, {
        headers: {
          "Content-Type": "application/json",
          "X-Auth-Key": `${checksum}`,
        },
      });

      return result.data.publickey;
    } catch (err) {
      Log.log(err, LogLevel.error);
      throw new CustomRestError(
        {
          code: 400,
          message: "can't load public key from public federation service",
        },
        400,
      );
    }
  }

  private async loadFederationRemoteInformation(domain: string): Promise<AxiosResponse> {
    try {
      const publicKey = await this.loadPublicKeyFromFederationService();
      const checksum = await this.loadLicenseChecksum();
      const host = await this.loadFederationHost();
      const requestBody = await this.encryptor.encryptBody(publicKey, { domain });
      const bodyChecksum = CryptionUtils.buildChecksumFromBody(requestBody);
      return await Axios.post(`${host.publicFederationSerivce}/api/v1/federation`, requestBody, {
        headers: {
          "Content-Type": "application/json",
          "X-Auth-Key": `${checksum}`,
          "X-Auth-Checksum": `${bodyChecksum}`,
        },
      });
    } catch (err) {
      Log.log(err, LogLevel.error);
      throw new CustomRestError(
        {
          code: 400,
          message: "can't load domain information from public federation service",
        },
        400,
      );
    }
  }

  private async federationRequest(publicFederationKey: string, email: string, domain: string, target: string): Promise<AxiosResponse> {
    const requestObject = {
      encryptedEmail: email,
      encryptedDomain: domain,
    };

    const cryptedFederationObject: any = await this.encryptor.encryptBody(publicFederationKey, requestObject);
    const cryptedFederationChecksum = CryptionUtils.buildChecksumFromBody(cryptedFederationObject);
    try {
      return await Axios.post(
        `http://${target}/api/v1/federation/user`,
        {
          encryptedEmail: cryptedFederationObject.encryptedEmail,
          encryptedDomain: cryptedFederationObject.encryptedDomain,
        },
        {
          headers: {
            "X-Federation-Checksum": cryptedFederationChecksum,
            "Content-Type": "application/json",
          },
        },
      );
    } catch (err) {
      Log.log(err, LogLevel.error);
      throw new CustomRestError(
        {
          code: 400,
          message: "Federation request to target service failed",
        },
        400,
      );
    }
  }
}
