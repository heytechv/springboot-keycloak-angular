import {APP_INITIALIZER, NgModule} from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppComponent } from './app.component';
import {initializer} from "../utils/app-init";
import {KeycloakAngularModule, KeycloakService} from "keycloak-angular";
import { AppRoutingModule } from './app-routing.module';
import { AccessDeniedComponent } from './access-denied/access-denied.component';
import { UserInfoComponent } from './user-info/user-info.component';
import {HttpClientModule} from "@angular/common/http";

@NgModule({
  declarations: [
    AppComponent,
    AccessDeniedComponent,
    UserInfoComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    KeycloakAngularModule,
    HttpClientModule
  ],
  providers: [
    {
      provide: APP_INITIALIZER,
      useFactory: initializer,
      deps: [ KeycloakService ],
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
