import { Component, OnInit } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {AuthService} from "../auth/auth.service";
import {WebApiService} from "../api/web-api.service";

@Component({
  selector: 'app-user-info',
  templateUrl: './user-info.component.html',
  styleUrls: ['./user-info.component.css']
})
export class UserInfoComponent implements OnInit {

  message: string = 'null';

  constructor(private authService: AuthService, private webApiService: WebApiService, private http: HttpClient) { }

  ngOnInit(): void {
    this.message = this.authService.getUsername();

    this.webApiService.getUserInfo().subscribe({
      next: data => {
        this.message += ", " + data;
      }, error: err => {
        console.log(err);
      }
    });

  }

}
