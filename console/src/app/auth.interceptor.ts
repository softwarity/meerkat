import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { catchError, throwError } from 'rxjs';

// A 401 means no valid session: hand the browser to the gateway's login page
// (served on this same origin) with a return path back into the console.
//
// ONCE, and that "once" is the whole point. A cold start fires several calls at
// the same time (/api/me, /api/tenants…) and they all come back 401 together.
// Assigning location.href per failure does not redirect harder: each assignment
// CANCELS the navigation the previous one started, so the browser keeps
// restarting it, never leaves the page, and shows a blank screen with nothing
// in the console to explain it. Cost: an afternoon of looking everywhere else.
let leaving = false;

export const authInterceptor: HttpInterceptorFn = (req, next) =>
  next(req).pipe(
    catchError((err: unknown) => {
      if (err instanceof HttpErrorResponse && err.status === 401 && !leaving) {
        leaving = true;
        const back = encodeURIComponent(location.pathname + location.search);
        location.href = `/login?next=${back}`;
      }
      return throwError(() => err);
    }),
  );
