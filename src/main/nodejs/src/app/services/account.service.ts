import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { share } from 'rxjs/operators';
import { Principal } from '../models/principal';
import { User } from '../models/user';

@Injectable({
  providedIn: 'root'
})
export class AccountService {
  private accountUrl = 'api/v1/account';
  private principal$ = null;

  constructor(
    private http: HttpClient
  ) { }

  getPrincipal(): Observable<Principal> {
    if (this.principal$ == null) {
      const url = `${this.accountUrl}/principal`;
      this.principal$ = this.http.get<Principal>(url).pipe(share());
    }
    return this.principal$;
  }

  updateUser(user: User): Observable<User> {
    const url = `${this.accountUrl}/user`;
    return this.http.post<User>(url, user);
  }
}
