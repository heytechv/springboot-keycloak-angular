import {Injectable} from "@angular/core";
import {KeycloakService} from "keycloak-angular";

@Injectable({
  providedIn: "root"
})
export class  AuthService {

  constructor(private keycloakService: KeycloakService) { }

  public getUsername(): string {
    return this.keycloakService.getUsername();
  }

  public logout(): void {
    this.keycloakService.logout().then(() => this.keycloakService.clearToken());
  }

}
