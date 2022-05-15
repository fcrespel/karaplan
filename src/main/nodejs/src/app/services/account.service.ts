import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { shareReplay, switchMapTo } from 'rxjs/operators';
import { Principal } from '../models/principal';
import { User } from '../models/user';

@Injectable({
  providedIn: 'root'
})
export class AccountService {
  private accountUrl = 'api/v1/account';
  private principal$?: Observable<Principal>;
  private principalRefresh$ = new BehaviorSubject<void>(undefined);
  private user$?: Observable<User>;
  private userRefresh$ = new BehaviorSubject<void>(undefined);

  constructor(
    private http: HttpClient
  ) { }

  getPrincipal(cache: boolean = true): Observable<Principal> {
    const url = `${this.accountUrl}/principal`;
    if (!cache) {
      return this.http.get<Principal>(url);
    } else if (this.principal$ === undefined) {
      this.principal$ = this.principalRefresh$.pipe(switchMapTo(this.http.get<Principal>(url)), shareReplay(1));
    }
    return this.principal$;
  }

  getUser(cache: boolean = true): Observable<User> {
    const url = `${this.accountUrl}/user`;
    if (!cache) {
      return this.http.get<User>(url);
    } else if (this.user$ === undefined) {
      this.user$ = this.userRefresh$.pipe(switchMapTo(this.http.get<User>(url)), shareReplay(1));
    }
    return this.user$;
  }

  updateUser(user: User): Observable<User> {
    const url = `${this.accountUrl}/user`;
    return this.http.post<User>(url, user);
  }

  deleteUser(deleteComments: boolean): Observable<void> {
    const url = `${this.accountUrl}/user?deleteComments=${deleteComments}`;
    this.refreshCache();
    return this.http.delete<void>(url);
  }

  refreshCache() {
    this.principalRefresh$.next(undefined);
    this.userRefresh$.next(undefined);
  }
}
