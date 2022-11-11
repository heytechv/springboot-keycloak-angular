import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {environment} from "../../environments/environment";
import {Observable} from "rxjs";

@Injectable({
  providedIn: 'root'
})
export class WebApiService {

  constructor(private http: HttpClient) { }

  public getUserInfo(): Observable<string> {
    return this.http.get(`${environment.apiUrl}/userInfo1`, {responseType:'text'});
  }

}
