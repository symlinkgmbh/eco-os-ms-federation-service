/**
 * Copyright 2018-2020 Symlink GmbH
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




import { IFederationContentHandler } from "./IFederationContentHandler";
import { PkCore, MsFederation, PkCrypt } from "@symlinkde/eco-os-pk-models";
import { injectable } from "inversify";
import { injectLicenseClient, injectContentClient } from "@symlinkde/eco-os-pk-core";
import * as forge from "node-forge";
import { CustomRestError } from "@symlinkde/eco-os-pk-api";
import { Log, LogLevel } from "@symlinkde/eco-os-pk-log";
import { CryptoWorker } from "@symlinkde/eco-os-pk-crypt";

@injectContentClient
@injectLicenseClient
@injectable()
export class FederationContentHandler implements IFederationContentHandler {
  private licenseClient!: PkCore.IEcoLicenseClient;
  private contentClient!: PkCore.IEcoContentClient;
  private privateLicenseKey!: string;
  private cryptoWorker: PkCrypt.ICryptoWorker;

  public constructor() {
    this.cryptoWorker = new CryptoWorker();
  }

  /**
   * Process incoming, encrypted post content sig.
   * @param content MsContent.IContent
   */
  public async handleIncomingContent(content: MsFederation.IFederationPostObject): Promise<any> {
    await this.loadPrivateKeyFromLicenseService();
    const decrypted = await this.cryptoWorker.decryptBody<MsFederation.IFederationPostObject>(content, this.privateLicenseKey);

    if (Array.isArray(decrypted.key)) {
      decrypted.key = decrypted.key.join("");
    }

    decrypted.domain = decrypted.sendingDomain;

    try {
      await this.contentClient.createContentFromFederation(decrypted);
      return;
    } catch (err) {
      Log.log(err, LogLevel.error);
      throw new CustomRestError(
        {
          code: 400,
          message: "Can´t post to internal content service",
        },
        400,
      );
    }
  }

  public async handleIncomingContentRequest(checksum: string, domain: string): Promise<any> {
    // TODO: Encrypt domain and check for blacklisted domain
    try {
      await this.loadPrivateKeyFromLicenseService();
      const decryptedChecksum = await this.decryptChecksum(checksum);
      const result = await this.contentClient.loadContentFromFederation(decryptedChecksum);
      return result.data;
    } catch (err) {
      Log.log(err, LogLevel.error);
      throw new CustomRestError(
        {
          code: 400,
          message: "can't load content",
        },
        400,
      );
    }
  }

  private async loadPrivateKeyFromLicenseService(): Promise<string> {
    if (!this.privateLicenseKey) {
      const result = await this.licenseClient.getPrivateKeyFromLicense();
      this.privateLicenseKey = result.data.privatekey;
    }
    return this.privateLicenseKey;
  }

  private async decryptChecksum(checksum: string): Promise<string> {
    return new Promise((resolve) => {
      try {
        const key: any = forge.pki.privateKeyFromPem(forge.util.decode64(this.privateLicenseKey));
        const dobj = forge.util.decode64(
          key.decrypt(forge.util.decode64(checksum), "RSA-OAEP", {
            md: forge.md.sha512.create(),
          }),
        );
        resolve(dobj);
      } catch (err) {
        Log.log(err, LogLevel.error);
        throw new CustomRestError(
          {
            code: 400,
            message: "Decryption for checksum failed",
          },
          400,
        );
      }
    });
  }
}
