import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { SongActionsComponent } from './song-actions.component';

describe('SongActionsComponent', () => {
  let component: SongActionsComponent;
  let fixture: ComponentFixture<SongActionsComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ SongActionsComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(SongActionsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
