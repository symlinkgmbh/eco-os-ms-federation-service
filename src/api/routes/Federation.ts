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




import { AbstractRoutes, injectValidatorService } from "@symlinkde/eco-os-pk-api";
import { PkApi } from "@symlinkde/eco-os-pk-models";
import { Application, Request, Response, NextFunction } from "express";
import { FederationController } from "../controllers";

@injectValidatorService
export class FederationRoute extends AbstractRoutes implements PkApi.IRoute {
  private federationController: FederationController = new FederationController();
  private validatorService!: PkApi.IValidator;
  private postInitFederationPattern: PkApi.IValidatorPattern = {
    domain: "",
  };

  private postResolveRemoteUserPattern: PkApi.IValidatorPattern = {
    email: "",
  };

  private postValdiateFederationPattern: PkApi.IValidatorPattern = {
    checksum: "",
    body: "",
  };

  private postResolveUser: PkApi.IValidatorPattern = {
    email: "",
    domain: "",
  };

  private getContentFromTargetDomainValidator: PkApi.IValidatorPattern = {
    checksum: "",
    domain: "",
  };

  constructor(app: Application) {
    super(app);
    this.activate();
  }

  public activate(): void {
    this.resolveDns();
    this.loadPublicKeyFromRemoteUser();
    this.validateFederationRequest();
    this.getUsersKeys();
    this.initFederationForDomain();
    this.postContentToTargetDomain();
    this.getContentFromTargetDomain();
    this.deliverRemoteContent();
    this.recieveRemoteContent();
    this.postContentToTargetDomainAsCommunitySystem();
  }

  private resolveDns(): void {
    this.getApp()
      .route("/federation/lookup")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.federationController
          .resolve2ndLock(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private loadPublicKeyFromRemoteUser(): void {
    this.getApp()
      .route("/federation/remote")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.validatorService.validate(req.body, this.postResolveRemoteUserPattern);
        this.federationController
          .loadRemoteUserPublicKeys(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private validateFederationRequest(): void {
    this.getApp()
      .route("/federation/validate")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.validatorService.validate(req.body, this.postValdiateFederationPattern);
        this.federationController
          .validateIncomingFederationRequest(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private getUsersKeys(): void {
    this.getApp()
      .route("/federation/user")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.validatorService.validate(req.body, this.postResolveUser);
        this.federationController
          .getUserKeys(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private initFederationForDomain(): void {
    this.getApp()
      .route("/federation/init")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.validatorService.validate(req.body, this.postInitFederationPattern);
        this.federationController
          .initFederation(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private postContentToTargetDomain(): void {
    this.getApp()
      .route("/federation/content")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.federationController
          .postContentToTargetDomain(req, false)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private postContentToTargetDomainAsCommunitySystem(): void {
    this.getApp()
      .route("/federation/content/community")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.federationController
          .postContentToTargetDomain(req, true)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private getContentFromTargetDomain(): void {
    this.getApp()
      .route("/federation/content/request")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.validatorService.validate(req.body, this.getContentFromTargetDomainValidator);
        this.federationController
          .requestRemoteContent(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private recieveRemoteContent(): void {
    this.getApp()
      .route("/federation/remote/content")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.federationController
          .receiveRemoteContent(req)
          .then(() => {
            res.sendStatus(200);
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private deliverRemoteContent(): void {
    this.getApp()
      .route("/federation/remote/deliver")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.federationController
          .deliverRemoteContent(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }
}
