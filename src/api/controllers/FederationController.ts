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




import { injectFederationService, IFederationService, injectFederationValidator, injectFederationContentHandler } from "../../infrastructure/federation";
import { Request } from "express";
import { RestError } from "@symlinkde/eco-os-pk-api";
import { SrvRecord } from "dns";
import { IFederationValidator } from "../../infrastructure/federation/IFederationValidator";
import { MsContent, MsFederation } from "@symlinkde/eco-os-pk-models";
import { IFederationContentHandler } from "../../infrastructure/federation/IFederationContentHandler";

@injectFederationService
@injectFederationValidator
@injectFederationContentHandler
export class FederationController {
  private federationService!: IFederationService;
  private federationValidator!: IFederationValidator;
  private federationContentHandler!: IFederationContentHandler;

  public async resolve2ndLock(req: Request): Promise<SrvRecord[]> {
    const result = await this.federationService.resolve2ndLock(req.body.domain);
    if (result === null) {
      throw new RestError("federation-service", "2ndlock not found", 404);
    }

    return result;
  }

  public async loadRemoteUserPublicKeys(req: Request): Promise<any> {
    return await this.federationService.resolveRemoteUserKeys(req.body.email);
  }

  public async initFederation(req: Request): Promise<any> {
    return await this.federationService.processFederationFromPublicFederationService(req.body.domain);
  }

  public async validateIncomingFederationRequest(req: Request): Promise<void> {
    return await this.federationValidator.validateIncomingFederationRequest(req.body.checksum, req.body.body);
  }

  public async getUserKeys(req: Request): Promise<any> {
    return await this.federationValidator.getUserInformation(req.body.email, req.body.domain);
  }

  public async postContentToTargetDomain(req: Request, isCommunitySystem: boolean): Promise<any> {
    return await this.federationService.postRemoteContent(req.body as MsFederation.IFederationPostObject, isCommunitySystem);
  }

  public async receiveRemoteContent(req: Request): Promise<any> {
    return await this.federationContentHandler.handleIncomingContent(req.body as MsContent.IContent);
  }

  public async deliverRemoteContent(req: Request): Promise<any> {
    const { checksum, domain } = req.body;
    return await this.federationContentHandler.handleIncomingContentRequest(checksum, domain);
  }

  public async requestRemoteContent(req: Request): Promise<any> {
    const { checksum, domain } = req.body;
    return await this.federationService.getRemoteContent(checksum, domain);
  }
}
