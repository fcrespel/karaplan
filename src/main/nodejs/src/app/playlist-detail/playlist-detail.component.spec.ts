import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { PlaylistDetailComponent } from './playlist-detail.component';

describe('PlaylistDetailComponent', () => {
  let component: PlaylistDetailComponent;
  let fixture: ComponentFixture<PlaylistDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ PlaylistDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(PlaylistDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
