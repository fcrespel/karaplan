import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Principal } from '../models/principal';

@Injectable({
  providedIn: 'root'
})
export class AccountService {
  private accountUrl = 'api/v1/account';

  constructor(
    private http: HttpClient
  ) { }

  getPrincipal(): Observable<Principal> {
    const url = `${this.accountUrl}/principal`;
    return this.http.get<Principal>(url);
  }
}
