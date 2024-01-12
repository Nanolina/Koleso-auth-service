import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  /**
   * Determines if the route can be activated.
   *
   * Checks if the @Public decorator is present in a controller or handler method.
   * If @Public is present, access to the route is allowed without checking the access token.
   *
   * @param {ExecutionContext} context - the context of the request execution.
   * @returns {boolean} - returns `true` if the route is publicly accessible (with the @Public decorator) or if the parent
   * canActivate function returns `true`.
   */
  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;

    return super.canActivate(context);
  }
}
