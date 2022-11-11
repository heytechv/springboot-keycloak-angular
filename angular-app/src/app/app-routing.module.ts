import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import {RouterModule, Routes} from "@angular/router";
import {AccessDeniedComponent} from "./access-denied/access-denied.component";
import {AuthGuard} from "./auth/auth.guard";
import {UserInfoComponent} from "./user-info/user-info.component";

const routes: Routes = [
  {
    path: 'access-denied',
    component: AccessDeniedComponent,
    canActivate: [AuthGuard]
  },
  {
    path: 'user-info',
    component: UserInfoComponent,
    canActivate: [AuthGuard],
    // The user need to have these roles to access page
    data: { roles: ['user'] }
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
