import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { TranslateService } from '@ngx-translate/core';
import { Subject } from 'rxjs';
import { filter, takeUntil } from 'rxjs/operators';
import { AlertComponent } from './alert/alert.component';
import { FooterComponent } from './footer/footer.component';
import { NavbarComponent } from './navbar/navbar.component';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
  imports: [NavbarComponent, AlertComponent, RouterOutlet, FooterComponent]
})
export class AppComponent implements OnInit, OnDestroy {
  private router = inject(Router);
  private translate = inject(TranslateService);

  currentRoute: string = '';
  destroy$: Subject<boolean> = new Subject<boolean>();

  ngOnInit() {
    this.translate.addLangs(['en', 'fr']);
    const lang = this.translate.getBrowserLang();
    if (lang && this.translate.getLangs().includes(lang)) {
      this.translate.use(lang);
    }
    this.router.events
      .pipe(takeUntil(this.destroy$))
      .pipe(filter((event: any) => event instanceof NavigationEnd))
      .subscribe((event: NavigationEnd) => this.currentRoute = event.urlAfterRedirects);
  }

  ngOnDestroy() {
    this.destroy$.next(true);
    this.destroy$.complete();
  }

}
