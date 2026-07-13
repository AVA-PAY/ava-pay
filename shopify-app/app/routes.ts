import { flatRoutes } from '@react-router/fs-routes';
import type { RouteConfig } from '@react-router/dev/routes';

// Same flat-file convention we used under Remix; route filenames unchanged.
export default flatRoutes({ ignoredRouteFiles: ['**/.*'] }) satisfies RouteConfig;
