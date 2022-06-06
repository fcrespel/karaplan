import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UserVotesComponent } from './user-votes.component';

describe('UserVotesComponent', () => {
  let component: UserVotesComponent;
  let fixture: ComponentFixture<UserVotesComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ UserVotesComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(UserVotesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
