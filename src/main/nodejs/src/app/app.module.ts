import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { NavbarComponent } from './navbar/navbar.component';
import { HomeComponent } from './home/home.component';
import { SongsComponent } from './songs/songs.component';
import { SongListComponent } from './song-list/song-list.component';
import { SongSelectionsComponent } from './song-selections/song-selections.component';
import { SongDetailComponent } from './song-detail/song-detail.component';
import { SongActionsComponent } from './song-actions/song-actions.component';
import { PlaylistsComponent } from './playlists/playlists.component';
import { PlaylistDetailComponent } from './playlist-detail/playlist-detail.component';
import { UserProfileComponent } from './user-profile/user-profile.component';
import { DurationPipe } from './pipes/duration.pipe';

@NgModule({
  declarations: [
    AppComponent,
    NavbarComponent,
    HomeComponent,
    SongsComponent,
    SongListComponent,
    SongSelectionsComponent,
    SongDetailComponent,
    SongActionsComponent,
    PlaylistsComponent,
    PlaylistDetailComponent,
    UserProfileComponent,
    DurationPipe
  ],
  imports: [
    BrowserModule,
    FormsModule,
    HttpClientModule,
    NgbModule,
    AppRoutingModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
