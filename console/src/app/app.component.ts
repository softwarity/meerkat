import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import {
  RailnavComponent,
  RailnavContainerComponent,
  RailnavContentComponent,
  RailnavItemComponent,
  RailnavSpacerComponent,
} from '@softwarity/rail-nav';
import { ApiService } from './api.service';

@Component({
  selector: 'app-root',
  imports: [
    RouterOutlet,
    MatIconModule,
    RailnavComponent,
    RailnavContainerComponent,
    RailnavContentComponent,
    RailnavItemComponent,
    RailnavSpacerComponent,
  ],
  styles: [
    `
      rail-nav-container {
        height: 100vh;
      }
      rail-nav-content {
        overflow: auto;
      }
    `,
  ],
  template: `
    <rail-nav-container>
      <rail-nav title="meerkat" subtitle="console">
        <rail-nav-item label="Routes" routerLink="/routes">
          <mat-icon>alt_route</mat-icon>
        </rail-nav-item>
        <rail-nav-spacer />
        <rail-nav-item label="Sign out" (click)="logout()">
          <mat-icon>logout</mat-icon>
        </rail-nav-item>
      </rail-nav>
      <rail-nav-content>
        <router-outlet />
      </rail-nav-content>
    </rail-nav-container>
  `,
})
export class AppComponent {
  private readonly api = inject(ApiService);

  constructor() {
    inject(MatIconRegistry).setDefaultFontSetClass('material-symbols-outlined');
  }

  logout(): void {
    this.api.logout().subscribe({
      next: () => (location.href = '/login'),
      error: () => (location.href = '/login'),
    });
  }
}
